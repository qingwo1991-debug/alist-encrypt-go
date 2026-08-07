package handler

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// stats_session.go — 服务端播放会话聚合。
//
// 播放器对单个文件发多条 Range 请求（首帧预取 + 多次 seek），每条若都落库，
// "播放次数"会虚高（实测一个视频 2 秒 7 条）。BoltStatsRecorder.RecordPlayback
// 把同一路径、活跃窗口内的多条 PlaybackEvent 合并为一条"播放会话"再写库：
//   - BytesServed / DurationSecs 累加
//   - SeekCount 累计"非首帧、非 0 起始位置、体量小"的请求数（近似快进/快退）
//   - 落库一条记录：一个文件一次播放 = 一条
//
// 与移动端 playbackSessionTracker 语义一致，服务端同样需要。

// 会话窗口：两次请求间隔超过该值视为新会话。
const serverPlaybackSessionWindow = 30 * time.Second

// 会话挂起上限：防异常退出丢数据 + 内存无限增长。
const serverPlaybackSessionMaxLifetime = 2 * time.Hour

// seek 判定阈值：起始位置 > 0 且体量 < 1MB 视为定位型预取。
const serverSeekRangeHintBytes = 1 << 20

type serverPlaybackSession struct {
	path         string
	provider     string
	contentType  string
	startAt      time.Time
	lastAt       time.Time
	bytesServed  int64
	totalBytes   int64
	durationSecs float64
	seekCount    int
}

// playbackRecorderWriter 聚合器落库目标（*StatsStore 实现）。
type playbackRecorderWriter interface {
	RecordPlayback(context.Context, PlaybackEvent) error
}

// serverPlaybackSessionAggregator 按路径聚合播放事件，flush 时写库。
type serverPlaybackSessionAggregator struct {
	mu       sync.Mutex
	sessions map[string]*serverPlaybackSession
	window   time.Duration
	writer   playbackRecorderWriter
	nowFn    func() time.Time
}

func newServerPlaybackSessionAggregator(writer playbackRecorderWriter) *serverPlaybackSessionAggregator {
	return &serverPlaybackSessionAggregator{
		sessions: make(map[string]*serverPlaybackSession),
		window:   serverPlaybackSessionWindow,
		writer:   writer,
		nowFn:    time.Now,
	}
}

// record 注入一条播放事件。同路径窗口内的请求并入会话不落库；
// 超窗/超龄的旧会话在此触发 flush 落库。
func (a *serverPlaybackSessionAggregator) record(ev PlaybackEvent) {
	if a == nil || a.writer == nil || ev.Path == "" || ev.BytesServed <= 0 {
		return
	}
	now := a.nowFn()
	seek := 0
	if ev.RangeStart > 0 && ev.BytesServed <= serverSeekRangeHintBytes {
		seek = 1
	}

	a.mu.Lock()
	for path, sess := range a.sessions {
		if now.Sub(sess.lastAt) > a.window || now.Sub(sess.startAt) > serverPlaybackSessionMaxLifetime {
			a.flushLocked(path, sess)
		}
	}
	sess := a.sessions[ev.Path]
	if sess == nil {
		sess = &serverPlaybackSession{
			path:        ev.Path,
			provider:    ev.Provider,
			contentType: ev.ContentType,
			startAt:     now,
			totalBytes:  ev.TotalBytes,
		}
		a.sessions[ev.Path] = sess
	}
	sess.lastAt = now
	sess.bytesServed += ev.BytesServed
	sess.durationSecs += ev.DurationSecs
	sess.seekCount += seek
	if ev.Completed {
		sess.contentType = ev.ContentType
	}
	a.mu.Unlock()
}

// flushLocked 把一条会话转 PlaybackEvent 写库。调用方持锁。
func (a *serverPlaybackSessionAggregator) flushLocked(path string, sess *serverPlaybackSession) {
	defer delete(a.sessions, path)
	if sess == nil || sess.bytesServed <= 0 {
		return
	}
	ev := PlaybackEvent{
		ID:           sess.startAt.Format("20060102T150405.000000000"),
		Path:         sess.path,
		Provider:     sess.provider,
		BytesServed:  sess.bytesServed,
		TotalBytes:   sess.totalBytes,
		DurationSecs: sess.durationSecs,
		PlayedAt:     sess.startAt,
		Completed:    true,
		ContentType:  sess.contentType,
		SeekCount:    sess.seekCount,
	}
	if err := a.writer.RecordPlayback(context.Background(), ev); err != nil {
		log.Warn().Err(err).Str("path", ev.Path).Msg("failed to persist aggregated playback session")
	}
}

// flushAll 落库所有会话（供导出前/进程退出调用）。
func (a *serverPlaybackSessionAggregator) flushAll() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for path, sess := range a.sessions {
		a.flushLocked(path, sess)
	}
}
