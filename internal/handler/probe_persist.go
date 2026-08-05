package handler

import (
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/storage"
)

// probe_persist.go — 预热统计的持久化。
//
// 预热数据（累计计数 + 文件级 warm 状态）原先全在内存 atomic/map 中，
// docker pull 重启后清零，运行摘要里"预热状态 0 ready"、命中率 0% 让用户
// 误以为预热没起作用。这里把两类数据落到 BoltDB `stats` bucket：
//
//   - probe:counters —— 累计计数（files_succeeded_total / consumer_hit_total 等）
//   - probe:warmstate —— successfulWarm map 快照（含 ConsumerHitCount）
//
// 热路径零开销：只在本文件的快照落盘点（周期 + Stop）写一次 JSON；
// 播放路径读 RawURL 来自 fileinfo，不经过这里。

const (
	probeCountersKey  = "probe:counters"
	probeWarmStateKey = "probe:warmstate"

	probePersistFlushInterval = 30 * time.Second
)

// ProbeCounters 持久化的累计计数器。字段与 ProbeScheduler.Stats() 对应，
// 只存"重启后值得保留"的趋势值。
type ProbeCounters struct {
	FilesSucceededTotal uint64 `json:"files_succeeded_total"`
	FilesFailedTotal    uint64 `json:"files_failed_total"`
	FilesSkippedTotal   uint64 `json:"files_skipped_total"`
	FilesRawURLFetched  uint64 `json:"files_raw_url_fetched"`
	FilesRangeProbed    uint64 `json:"files_range_probed"`
	FilesMetaPersisted  uint64 `json:"files_meta_persisted"`
	FilesDiscovered     uint64 `json:"files_discovered_total"`
	FilesQueued         uint64 `json:"files_queued_total"`
	EnqueuedTotal       uint64 `json:"enqueued_total"`
	DroppedTotal        uint64 `json:"dropped_total"`
	CooldownSkips       uint64 `json:"cooldown_skips"`
	ConsumerHitTotal    uint64 `json:"consumer_hit_total"`
	InvalidationsTotal  uint64 `json:"invalidations_total"`
}

// probePersister 封装 BoltDB 的预热数据读写。nil-safe。
type probePersister struct {
	store *storage.Store
}

func newProbePersister(store *storage.Store) *probePersister {
	if store == nil {
		return nil
	}
	return &probePersister{store: store}
}

// loadCounters 读取持久化计数，返回 nil 表示无/失败（视为全新开始）。
func (pp *probePersister) loadCounters() *ProbeCounters {
	if pp == nil {
		return nil
	}
	var c ProbeCounters
	if err := pp.store.GetJSON(storage.BucketStats, probeCountersKey, &c); err != nil {
		return nil
	}
	return &c
}

// saveCounters 覆盖写计数。失败仅记日志（统计非关键路径）。
func (pp *probePersister) saveCounters(c *ProbeCounters) {
	if pp == nil || pp.store == nil || c == nil {
		return
	}
	if err := pp.store.SetJSON(storage.BucketStats, probeCountersKey, c); err != nil {
		log.Warn().Err(err).Msg("failed to persist probe counters")
	}
}

// loadWarmState 读取 warm map 快照，返回 nil 表示无/失败。
func (pp *probePersister) loadWarmState() map[string]probeWarmState {
	if pp == nil {
		return nil
	}
	var m map[string]probeWarmState
	if err := pp.store.GetJSON(storage.BucketStats, probeWarmStateKey, &m); err != nil {
		return nil
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// saveWarmState 覆盖写 warm map 快照。
func (pp *probePersister) saveWarmState(m map[string]probeWarmState) {
	if pp == nil || pp.store == nil || m == nil {
		return
	}
	if err := pp.store.SetJSON(storage.BucketStats, probeWarmStateKey, m); err != nil {
		log.Warn().Err(err).Msg("failed to persist probe warm state")
	}
}

// loadPersistedState 启动时把 BoltDB 里的计数与 warm 状态装回内存。
// 计数直接覆盖（持久化的是权威累计值）；warm 状态合并进 successfulWarm。
func (ps *ProbeScheduler) loadPersistedState() {
	if ps == nil {
		return
	}
	ps.persister = newProbePersister(ps.store)
	if ps.persister == nil {
		return
	}
	if c := ps.persister.loadCounters(); c != nil {
		ps.ensureRecordState()
		atomic.StoreUint64(&ps.filesSucceededTotal, c.FilesSucceededTotal)
		atomic.StoreUint64(&ps.filesFailedTotal, c.FilesFailedTotal)
		atomic.StoreUint64(&ps.filesSkippedTotal, c.FilesSkippedTotal)
		atomic.StoreUint64(&ps.filesRawURLFetched, c.FilesRawURLFetched)
		atomic.StoreUint64(&ps.filesRangeProbed, c.FilesRangeProbed)
		atomic.StoreUint64(&ps.filesMetaPersisted, c.FilesMetaPersisted)
		atomic.StoreUint64(&ps.filesDiscoveredTotal, c.FilesDiscovered)
		atomic.StoreUint64(&ps.filesQueuedTotal, c.FilesQueued)
		atomic.StoreUint64(&ps.enqueuedTotal, c.EnqueuedTotal)
		atomic.StoreUint64(&ps.droppedTotal, c.DroppedTotal)
		atomic.StoreUint64(&ps.cooldownSkips, c.CooldownSkips)
		atomic.StoreUint64(&ps.consumerHitTotal, c.ConsumerHitTotal)
		atomic.StoreUint64(&ps.invalidationsTotal, c.InvalidationsTotal)
	}
	if warm := ps.persister.loadWarmState(); warm != nil {
		ps.ensureRecordState()
		ps.recordMu.Lock()
		for k, v := range warm {
			if _, exists := ps.successfulWarm[k]; !exists {
				ps.successfulWarm[k] = v
			}
		}
		ps.recordMu.Unlock()
	}
}

// startPersistLoop 周期把当前计数与 warm 状态落盘，直到 ctx 取消。
func (ps *ProbeScheduler) startPersistLoop() {
	if ps == nil || ps.persister == nil {
		return
	}
	ps.workerWG.Add(1)
	go func() {
		defer ps.workerWG.Done()
		ticker := time.NewTicker(probePersistFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ps.done():
				return
			case <-ticker.C:
				ps.persistSnapshot()
			}
		}
	}()
}

// persistSnapshot 把当前内存态写回 BoltDB。不持有锁快照（低频、容忍略旧）。
func (ps *ProbeScheduler) persistSnapshot() {
	if ps == nil || ps.persister == nil {
		return
	}
	c := &ProbeCounters{
		FilesSucceededTotal: atomic.LoadUint64(&ps.filesSucceededTotal),
		FilesFailedTotal:    atomic.LoadUint64(&ps.filesFailedTotal),
		FilesSkippedTotal:   atomic.LoadUint64(&ps.filesSkippedTotal),
		FilesRawURLFetched:  atomic.LoadUint64(&ps.filesRawURLFetched),
		FilesRangeProbed:    atomic.LoadUint64(&ps.filesRangeProbed),
		FilesMetaPersisted:  atomic.LoadUint64(&ps.filesMetaPersisted),
		FilesDiscovered:     atomic.LoadUint64(&ps.filesDiscoveredTotal),
		FilesQueued:         atomic.LoadUint64(&ps.filesQueuedTotal),
		EnqueuedTotal:       atomic.LoadUint64(&ps.enqueuedTotal),
		DroppedTotal:        atomic.LoadUint64(&ps.droppedTotal),
		CooldownSkips:       atomic.LoadUint64(&ps.cooldownSkips),
		ConsumerHitTotal:    atomic.LoadUint64(&ps.consumerHitTotal),
		InvalidationsTotal:  atomic.LoadUint64(&ps.invalidationsTotal),
	}
	ps.persister.saveCounters(c)
	ps.persistWarmStateSnapshot()
}

// persistWarmStateSnapshot 把 successfulWarm 复制一份落盘。
func (ps *ProbeScheduler) persistWarmStateSnapshot() {
	if ps == nil || ps.persister == nil {
		return
	}
	ps.ensureRecordState()
	ps.recordMu.Lock()
	snapshot := make(map[string]probeWarmState, len(ps.successfulWarm))
	for k, v := range ps.successfulWarm {
		snapshot[k] = v
	}
	ps.recordMu.Unlock()
	ps.persister.saveWarmState(snapshot)
}
