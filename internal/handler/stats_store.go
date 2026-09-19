package handler

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/storage"
)

// 播放/删除统计的本地持久化（BoltDB `stats` bucket）。
//
// 设计目标：为未来导出给 AI 做推荐提供结构化事件数据。记录两类事件：
//   - 播放事件（PlaybackEvent）：某文件真实被播放（有字节写出），含路径、provider、
//     播放字节数、时长估计、时间。
//   - 删除事件（DeletionEvent）：某文件被删除，含路径、删除时间、"距最后一次播放
//     的间隔"（由播放事件反查）。
//
// 存储：每个事件一条 JSON，key 形如 "play:01HEX...|path" / "del:01HEX...|path"，
// 用时间戳+随机后缀保证唯一且按时间近似有序。
//
// 写入路径（性能）：
//   - 请求侧只做内存合并 + 入队（有界队列）。写 BoltDB 由单个后台 writer 负责，
//     批量合并为一次写事务，播放/删除热路径不感知磁盘。
//   - 读取/导出/清空前会先同步冲刷队列（write-through read），保证"刚写入立刻可
//     读"的语义不变。
//   - 删除反查"最后一次播放"走 last_play 索引（单 key 点查），不再全桶扫描。
//   - 超标裁剪改为后台定时 + 队列水位双触发，完全离出请求路径。

const (
	statsKeyPlayPrefix = "play:"
	statsKeyDelPrefix  = "del:"
	lastPlayKeyPrefix  = "last_play:"
	statsMaxEvents     = 200000 // 单端事件上限，超过则清理最旧

	// statsWriteQueueCap 有界队列容量；满则丢弃（计数）而不阻塞播放。
	statsWriteQueueCap = 4096
	// statsFlushInterval 后台 writer 空闲时的合并周期；突发事件会立刻唤醒即冲。
	statsFlushInterval = 100 * time.Millisecond
	// statsPruneThreshold 入队事件达到该水位后，在下次冲刷时检查事件上限。
	statsPruneThreshold = 2000
	// statsPruneInterval 定时兜底，保证长时间无写入也会自检。
	statsPruneInterval = 5 * time.Minute
)

// PlaybackEvent 一次真实播放（有字节写出的范围请求/流式）。
// 会话聚合后：同路径 30s 窗口内的多条 Range 请求合并为一条记录，
// SeekCount 累计窗口内的 seek 次数。
type PlaybackEvent struct {
	ID              string    `json:"id"`
	Path            string    `json:"path"`          // 展示路径（明文）
	Provider        string    `json:"provider"`      // provider host（归一化）
	BytesServed     int64     `json:"bytes_served"`  // 本次写出的解密字节数
	TotalBytes      int64     `json:"total_bytes"`   // 文件总大小
	DurationSecs    float64   `json:"duration_secs"` // 估计播放时长（秒）
	PlayedAt        time.Time `json:"played_at"`
	Completed       bool      `json:"completed"` // 是否完整写出（非客户端中断）
	ContentType     string    `json:"content_type,omitempty"`
	RangeStart      int64     `json:"range_start,omitempty"`       // 本请求 Range 起始位置（无 Range 为 0）
	SeekCount       int       `json:"seek_count"`                  // 会话内快进/快退次数
	HeaderLatencyMs float64   `json:"header_latency_ms,omitempty"` // 请求→响应头就绪，毫秒；0 表示未测量
	Mbps            float64   `json:"mbps,omitempty"`              // 本请求平均下行速率（MiB/s），0 表示未测量
}

// DeletionEvent 一次文件删除。
type DeletionEvent struct {
	ID                string    `json:"id"`
	Path              string    `json:"path"` // 展示路径（明文）
	DeletedAt         time.Time `json:"deleted_at"`
	LastPlayAt        time.Time `json:"last_play_at,omitempty"` // 最后一次播放时间（无则零值）
	SinceLastPlaySecs float64   `json:"since_last_play_secs"`   // 最后播放→删除间隔（秒），无播放为 -1
}

// lastPlayIndex 是按路径持久化的"最近一次播放"索引：display path → time，
// key 用 SHA-1 缩短，与播放事件在同一批写事务中更新。
type lastPlayIndex struct {
	Path string    `json:"path"`
	At   time.Time `json:"at"`
}

func lastPlayHashKey(path string) string {
	sum := sha1.Sum([]byte(path))
	return lastPlayKeyPrefix + hex.EncodeToString(sum[:])
}

// statsPendingWrite 一条排队中的待落库写入。播放事件边上可能带一个必须与事件
// 原子落库的 last-play 索引更新。
type statsPendingWrite struct {
	prefix string
	key    string
	value  interface{}
	// lastPlayPath/lastPlayAt：非空表示本事件是新路径的最近播放，需同时写索引。
	lastPlayPath string
	lastPlayAt   time.Time
}

// StatsStore 提供播放/删除统计的本地读写。写入非阻塞：请求侧只做内存合并与入队，
// 后台 writer 批量落库；读取会先冲刷队列保证写读一致。
type StatsStore struct {
	store *storage.Store

	mu               sync.Mutex
	pending          []statsPendingWrite
	lastPlay         map[string]time.Time // 内存 last-play 索引（path → time）
	stopped          bool
	eventsSincePrune int
	pruneLater       atomic.Bool

	stopCh  chan struct{}
	doneCh  chan struct{}
	running atomic.Bool
	dropped atomic.Int64 // 队列满载被丢弃的事件数（观测）
}

func NewStatsStore(store *storage.Store) *StatsStore {
	if store == nil {
		return nil
	}
	s := &StatsStore{
		store:    store,
		lastPlay: make(map[string]time.Time),
		stopCh:   make(chan struct{}, 1),
		doneCh:   make(chan struct{}),
	}
	s.running.Store(true)
	go s.loop()
	return s
}

// statsKey 构造唯一 key：prefix + 纳秒时间戳 + 转义后的 path。
func statsKey(prefix string, ts time.Time, path string) string {
	escaped := strings.ReplaceAll(path, "|", "%7C")
	return fmt.Sprintf("%s%020d|%s", prefix, ts.UnixNano(), escaped)
}

func statsPathFromKey(key string) string {
	idx := strings.IndexByte(key, '|')
	if idx < 0 {
		return key
	}
	escaped := key[idx+1:]
	return strings.ReplaceAll(escaped, "%7C", "|")
}

// enqueue 非阻塞入队。队列满时丢弃并计数，绝不让统计阻塞播放路径。
func (s *StatsStore) enqueue(item statsPendingWrite) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	if len(s.pending) >= statsWriteQueueCap {
		s.mu.Unlock()
		s.dropped.Add(1)
		log.Warn().Str("prefix", item.prefix).Msg("stats write queue full; dropping event")
		return
	}
	s.pending = append(s.pending, item)

	// 同步更新内存 last-play 索引；只有"比已知更新"的播放才带索引写。
	if item.lastPlayPath != "" {
		if at, ok := s.lastPlay[item.lastPlayPath]; !ok || item.lastPlayAt.After(at) {
			s.lastPlay[item.lastPlayPath] = item.lastPlayAt
		} else if item.lastPlayAt.Before(at) {
			// 旧事件不覆盖索引：清除随带的索引写。
			item.lastPlayPath = ""
		}
	}
	s.eventsSincePrune++
	needPrune := s.eventsSincePrune >= statsPruneThreshold
	s.mu.Unlock()

	if needPrune {
		s.pruneLater.Store(true)
	}
}

// flushPending 同步冲刷排队事件（读取/导出/清空/停服时调用）。可并发重复调用。
func (s *StatsStore) flushPending() error {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := s.pending
	s.pending = nil
	prune := s.pruneLater.Swap(false)
	s.mu.Unlock()

	if len(batch) > 0 {
		if err := s.writeBatch(batch); err != nil {
			log.Warn().Err(err).Int("events", len(batch)).Msg("stats write batch failed")
			// 出错时保留在内存，不阻塞调用方；后续冲刷会重试。
			s.mu.Lock()
			s.pending = append(batch, s.pending...)
			s.mu.Unlock()
			return err
		}
	}
	if prune {
		if err := s.pruneIfMoreThanMax(); err != nil {
			log.Warn().Err(err).Msg("stats prune failed")
		}
	}
	return nil
}

// writeBatch 把一批事件写成一次 BoltDB 写事务；last-play 索引与事件同批原子更新。
func (s *StatsStore) writeBatch(batch []statsPendingWrite) error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.UpdateBucket(storage.BucketStats, func(tx *storage.BucketTx) error {
		for _, item := range batch {
			if item.key == "" {
				continue
			}
			if item.lastPlayPath != "" {
				idx := lastPlayIndex{Path: item.lastPlayPath, At: item.lastPlayAt}
				if err := tx.SetJSON(lastPlayHashKey(item.lastPlayPath), &idx); err != nil {
					return err
				}
			}
			if err := tx.SetJSON(item.key, item.value); err != nil {
				return err
			}
		}
		return nil
	})
}

// RecordPlayback 记录一次播放事件（入队后立即返回，不阻塞）。
func (s *StatsStore) RecordPlayback(_ context.Context, ev PlaybackEvent) error {
	if s == nil || s.store == nil {
		return nil
	}
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if ev.PlayedAt.IsZero() {
		ev.PlayedAt = time.Now()
	}
	key := statsKey(statsKeyPlayPrefix, ev.PlayedAt, ev.Path)
	s.enqueue(statsPendingWrite{
		prefix:       statsKeyPlayPrefix,
		key:          key,
		value:        ev,
		lastPlayPath: ev.Path,
		lastPlayAt:   ev.PlayedAt,
	})
	return nil
}

// RecordDeletion 记录一次删除事件，通过 last-play 索引反查该路径上次播放时间。
func (s *StatsStore) RecordDeletion(_ context.Context, path string) error {
	if s == nil || s.store == nil {
		return nil
	}
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil
	}
	lastPlay, ok := s.lastPlayForPath(trimmed)
	ev := DeletionEvent{
		ID:         fmt.Sprintf("%d", time.Now().UnixNano()),
		Path:       trimmed,
		DeletedAt:  time.Now(),
		LastPlayAt: lastPlay,
	}
	if ok {
		ev.SinceLastPlaySecs = ev.DeletedAt.Sub(lastPlay).Seconds()
	} else {
		ev.SinceLastPlaySecs = -1
	}
	key := statsKey(statsKeyDelPrefix, ev.DeletedAt, trimmed)
	s.enqueue(statsPendingWrite{
		prefix: statsKeyDelPrefix,
		key:    key,
		value:  ev,
	})
	return nil
}

// lastPlayForPath 读取 last-play 索引：内存优先；未命中则单次点查持久化索引 key。
func (s *StatsStore) lastPlayForPath(path string) (time.Time, bool) {
	if s == nil || s.store == nil {
		return time.Time{}, false
	}
	s.mu.Lock()
	if at, ok := s.lastPlay[path]; ok {
		s.mu.Unlock()
		return at, true
	}
	s.mu.Unlock()

	var idx lastPlayIndex
	if err := s.store.GetJSON(storage.BucketStats, lastPlayHashKey(path), &idx); err == nil && !idx.At.IsZero() {
		s.mu.Lock()
		s.lastPlay[path] = idx.At
		s.mu.Unlock()
		return idx.At, true
	}
	return time.Time{}, false
}

// ListPlayback 按时间升序返回播放事件。先冲刷队列保证"刚写入可见"。
func (s *StatsStore) ListPlayback(ctx context.Context, limit int) ([]PlaybackEvent, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	_ = s.flushPending()

	all, err := s.store.GetAll(storage.BucketStats)
	if err != nil {
		return nil, err
	}
	out := make([]PlaybackEvent, 0, len(all))
	for key, raw := range all {
		if !strings.HasPrefix(key, statsKeyPlayPrefix) {
			continue
		}
		var ev PlaybackEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			continue
		}
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PlayedAt.Before(out[j].PlayedAt) })
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// ListDeletions 按时间升序返回删除事件。先冲刷队列。
func (s *StatsStore) ListDeletions(ctx context.Context, limit int) ([]DeletionEvent, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	_ = s.flushPending()

	all, err := s.store.GetAll(storage.BucketStats)
	if err != nil {
		return nil, err
	}
	out := make([]DeletionEvent, 0, len(all))
	for key, raw := range all {
		if !strings.HasPrefix(key, statsKeyDelPrefix) {
			continue
		}
		var ev DeletionEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			continue
		}
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeletedAt.Before(out[j].DeletedAt) })
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// pruneIfMoreThanMax 事件超过上限时清理最旧的。仅在后台路径触发（水位/定时）。
func (s *StatsStore) pruneIfMoreThanMax() error {
	if s == nil || s.store == nil {
		return nil
	}
	all, err := s.store.GetAll(storage.BucketStats)
	if err != nil {
		return err
	}
	if len(all) <= statsMaxEvents {
		return nil
	}
	var keys []string
	for k := range all {
		if strings.HasPrefix(k, lastPlayKeyPrefix) {
			continue // 索引不参与裁剪：体积小且删除反查依赖它
		}
		keys = append(keys, k)
	}
	sort.Strings(keys) // 前缀时间戳排序 → 最旧的在前
	if len(keys) <= statsMaxEvents {
		return nil
	}
	toDelete := keys[:len(keys)-statsMaxEvents]
	if len(toDelete) == 0 {
		return nil
	}
	return s.store.UpdateBucket(storage.BucketStats, func(tx *storage.BucketTx) error {
		for _, k := range toDelete {
			tx.Delete(k)
		}
		return nil
	})
}

// ClearPlaybackStats 清空所有播放/删除统计（含 last-play 索引），保留预热计数等其他键。
func (s *StatsStore) ClearPlaybackStats() error {
	if s == nil || s.store == nil {
		return nil
	}
	// 先冲刷队列，避免"清空"后又补写回一批。
	if err := s.flushPending(); err != nil {
		log.Warn().Err(err).Msg("stats clear: flush pending failed")
	}
	s.mu.Lock()
	s.lastPlay = make(map[string]time.Time)
	s.eventsSincePrune = 0
	s.mu.Unlock()

	all, err := s.store.GetAll(storage.BucketStats)
	if err != nil {
		return err
	}
	var toDelete []string
	for k := range all {
		if strings.HasPrefix(k, statsKeyPlayPrefix) ||
			strings.HasPrefix(k, statsKeyDelPrefix) ||
			strings.HasPrefix(k, lastPlayKeyPrefix) {
			toDelete = append(toDelete, k)
		}
	}
	if len(toDelete) == 0 {
		return nil
	}
	return s.store.UpdateBucket(storage.BucketStats, func(tx *storage.BucketTx) error {
		for _, k := range toDelete {
			tx.Delete(k)
		}
		return nil
	})
}

// DroppedQueueEvents 返回因队列满载被丢弃的事件数（观测）。
func (s *StatsStore) DroppedQueueEvents() int64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

// Stop 停止后台 writer 并做最终冲刷，保证进程退出不丢统计尾巴。
func (s *StatsStore) Stop() {
	if s == nil {
		return
	}
	if !s.running.CompareAndSwap(true, false) {
		return
	}
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	select {
	case s.stopCh <- struct{}{}:
	default:
	}
	<-s.doneCh
}

// loop 后台 writer：收到唤醒或定时即冲刷；定时查事件上限；Stop 时最终冲刷并退出。
func (s *StatsStore) loop() {
	defer close(s.doneCh)
	flushTick := time.NewTicker(statsFlushInterval)
	defer flushTick.Stop()
	pruneTick := time.NewTicker(statsPruneInterval)
	defer pruneTick.Stop()
	for {
		select {
		case <-s.stopCh:
			flushTick.Stop()
			pruneTick.Stop()
			if err := s.flushPending(); err != nil {
				log.Warn().Err(err).Msg("stats final flush failed")
			}
			if err := s.pruneIfMoreThanMax(); err != nil {
				log.Warn().Err(err).Msg("stats final prune failed")
			}
			return
		case <-flushTick.C:
			_ = s.flushPending()
		case <-pruneTick.C:
			if err := s.pruneIfMoreThanMax(); err != nil {
				log.Warn().Err(err).Msg("stats periodic prune failed")
			}
		}
	}
}

// BoltStatsRecorder 实现 StatsRecorder，把播放事件写入 StatsStore。
// 播放事件先经会话聚合器合并（同路径 30s 窗口内的 Range 请求算一次播放），
// 避免"播放次数"被播放器的多次 Range/seek 请求虚高。
type BoltStatsRecorder struct {
	store      *StatsStore
	aggregator *serverPlaybackSessionAggregator
}

func NewBoltStatsRecorder(store *StatsStore) *BoltStatsRecorder {
	if store == nil {
		return nil
	}
	r := &BoltStatsRecorder{store: store}
	r.aggregator = newServerPlaybackSessionAggregator(store)
	return r
}

// RecordPlayback 把播放事件喂给会话聚合器；窗口内合并，超窗才落库。
func (r *BoltStatsRecorder) RecordPlayback(ev PlaybackEvent) {
	if r == nil || r.aggregator == nil {
		return
	}
	r.aggregator.record(ev)
}

// FlushSessions 落库所有进行中的播放会话（导出前调用，保证统计完整）。
func (r *BoltStatsRecorder) FlushSessions() {
	if r == nil || r.aggregator == nil {
		return
	}
	r.aggregator.flushAll()
}

// RecordDeletion 异步写入删除事件。
func (r *BoltStatsRecorder) RecordDeletion(path string) {
	if r == nil || r.store == nil || path == "" {
		return
	}
	if err := r.store.RecordDeletion(context.Background(), path); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("failed to record deletion stats")
	}
}

// bytesPerSecToMbps converts bytes/second to MiB/second for playback rate
// observability. Returns 0 for non-positive input.
func bytesPerSecToMbps(bps float64) float64 {
	if bps <= 0 {
		return 0
	}
	return bps / (1024 * 1024)
}
