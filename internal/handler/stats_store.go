package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
//     的间隔"（由播放事件表反查）。
//
// 存储：每个事件一条 JSON，key 形如 "play:01HEX...|path" / "del:01HEX...|path"，
// 用时间戳+随机后缀保证唯一且按时间近似有序，便于后续按时间导出。

const (
	statsKeyPlayPrefix = "play:"
	statsKeyDelPrefix  = "del:"
	statsMaxEvents     = 200000 // 单端事件上限，超过则清理最旧
)

// PlaybackEvent 一次真实播放（有字节写出的范围请求/流式）。
// 会话聚合后：同路径 30s 窗口内的多条 Range 请求合并为一条记录，
// SeekCount 累计窗口内的 seek 次数。
type PlaybackEvent struct {
	ID            string    `json:"id"`
	Path          string    `json:"path"`            // 展示路径（明文）
	Provider      string    `json:"provider"`        // provider host（归一化）
	BytesServed   int64     `json:"bytes_served"`    // 本次写出的解密字节数
	TotalBytes    int64     `json:"total_bytes"`     // 文件总大小
	DurationSecs  float64   `json:"duration_secs"`   // 估计播放时长（秒），可能为 0
	PlayedAt      time.Time `json:"played_at"`
	Completed     bool      `json:"completed"`       // 是否完整写出（非客户端中断）
	ContentType   string    `json:"content_type,omitempty"`
	RangeStart    int64     `json:"range_start,omitempty"` // 本请求 Range 起始位置（无 Range 为 0）
	SeekCount     int       `json:"seek_count"`            // 会话内快进/快退次数
}

// DeletionEvent 一次文件删除。
type DeletionEvent struct {
	ID               string    `json:"id"`
	Path             string    `json:"path"`              // 展示路径（明文）
	DeletedAt        time.Time `json:"deleted_at"`
	LastPlayAt       time.Time `json:"last_play_at,omitempty"` // 最后一次播放时间（无则零值）
	SinceLastPlaySecs float64   `json:"since_last_play_secs"`  // 最后播放→删除间隔（秒），无播放为 -1
}

// StatsStore 提供播放/删除统计的本地读写。
type StatsStore struct {
	store *storage.Store
}

func NewStatsStore(store *storage.Store) *StatsStore {
	if store == nil {
		return nil
	}
	return &StatsStore{store: store}
}

// statsKey 构造唯一 key。prefix 为 play:/del:，ts 纳秒时间戳，path 明文（转义）。
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

// RecordPlayback 记录一次播放事件。
func (s *StatsStore) RecordPlayback(ctx context.Context, ev PlaybackEvent) error {
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
	if err := s.store.SetJSON(storage.BucketStats, key, ev); err != nil {
		return err
	}
	return s.pruneLockedIfNeeded()
}

// RecordDeletion 记录一次删除事件，并反查该路径最后一次播放时间。
func (s *StatsStore) RecordDeletion(ctx context.Context, path string) error {
	if s == nil || s.store == nil {
		return nil
	}
	if strings.TrimSpace(path) == "" {
		return nil
	}
	lastPlay, ok := s.lastPlayForPath(ctx, path)
	ev := DeletionEvent{
		ID:         fmt.Sprintf("%d", time.Now().UnixNano()),
		Path:       path,
		DeletedAt:  time.Now(),
		LastPlayAt: lastPlay,
	}
	if ok {
		ev.SinceLastPlaySecs = ev.DeletedAt.Sub(lastPlay).Seconds()
	} else {
		ev.SinceLastPlaySecs = -1
	}
	key := statsKey(statsKeyDelPrefix, ev.DeletedAt, path)
	if err := s.store.SetJSON(storage.BucketStats, key, ev); err != nil {
		return err
	}
	return s.pruneLockedIfNeeded()
}

// lastPlayForPath 在该路径的所有播放事件中找最近一次。
func (s *StatsStore) lastPlayForPath(_ context.Context, path string) (time.Time, bool) {
	all, err := s.store.GetAll(storage.BucketStats)
	if err != nil {
		return time.Time{}, false
	}
	var latest time.Time
	found := false
	for key, raw := range all {
		if !strings.HasPrefix(key, statsKeyPlayPrefix) {
			continue
		}
		if statsPathFromKey(key) != path {
			continue
		}
		var ev PlaybackEvent
		if json.Unmarshal(raw, &ev) != nil {
			continue
		}
		if !found || ev.PlayedAt.After(latest) {
			latest = ev.PlayedAt
			found = true
		}
	}
	return latest, found
}

// ListPlayback 按时间升序返回播放事件。
func (s *StatsStore) ListPlayback(ctx context.Context, limit int) ([]PlaybackEvent, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
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

// ListDeletions 按时间升序返回删除事件。
func (s *StatsStore) ListDeletions(ctx context.Context, limit int) ([]DeletionEvent, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
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

// pruneLockedIfNeeded 事件过多时清理最旧的（超上限时删除一半最旧的）。
func (s *StatsStore) pruneLockedIfNeeded() error {
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
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 前缀时间戳排序 → 最旧的在前
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

// ClearPlaybackStats 清空所有播放/删除统计事件（保留预热计数等其他键）。
func (s *StatsStore) ClearPlaybackStats() error {
	if s == nil || s.store == nil {
		return nil
	}
	all, err := s.store.GetAll(storage.BucketStats)
	if err != nil {
		return err
	}
	var toDelete []string
	for k := range all {
		if strings.HasPrefix(k, statsKeyPlayPrefix) || strings.HasPrefix(k, statsKeyDelPrefix) {
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

// BoltStatsRecorder 实现 StatsRecorder，把播放事件写入 StatsStore。
// 播放事件先经会话聚合器合并（同路径 30s 窗口内的 Range 请求算一次播放），
// 避免"播放次数"被播放器的多次 Range/seek 请求虚高。
type BoltStatsRecorder struct {
	store       *StatsStore
	aggregator  *serverPlaybackSessionAggregator
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
// 失败仅记日志不阻塞播放。
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
