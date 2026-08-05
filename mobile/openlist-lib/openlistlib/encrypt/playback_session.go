package encrypt

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

// playback_session.go — 播放会话聚合。
//
// 播放器对单个文件通常发多条 Range 流式请求（首帧预取 + 多次 seek），
// 若每条都落库，导出给 AI 时噪声极大。本聚合器把同一路径、活跃窗口内的
// 多条流式请求合并为"一次播放会话"再落库：
//   - BytesServed 累加，DurationSecs 用会话起止墙钟（含 seek 间隔）
//   - SeekCount 累加会话内"非首帧、非 0 起始位置"的 Range 请求次数
//     （近似快进/快退次数）
//   - 落库一条记录：一个文件一次播放 = 一条
//
// 会话边界：路径切换，或空闲超过 playbackSessionWindow（默认 30s）。

// playbackSessionWindow 两次请求间隔超过该值视为新会话。
// 大于播放器 seek 间隔，低于"暂停再继续播放"的常见间隔。
const playbackSessionWindow = 30 * time.Second

// playbackSessionMaxLifetime 会话挂起上限：超过则强制落库，
// 防止异常退出（进程被杀）丢太久的数据，也防内存无限增长。
const playbackSessionMaxLifetime = 2 * time.Hour

// seekRangeHintBytes 起始位置 > 0 且请求体量小于该值时视为"定位型"请求
// （seek 预取），而非连续播放段。1MB 对大多数视频首帧/seek 预取足够。
const seekRangeHintBytes = 1 << 20

type playbackSession struct {
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

// playbackSessionTracker 按路径聚合播放会话，并负责最终落库。
// playbackRecorder 落库目标的最小接口（真实实现是 *localStore，测试可替身）。
type playbackRecorder interface {
	AppendPlayback(rec PlaybackStatsRecord) error
}

type playbackSessionTracker struct {
	mu       sync.Mutex
	sessions map[string]*playbackSession
	window   time.Duration
	store    playbackRecorder
	nowFn    func() time.Time // 便于测试注入
}

func newPlaybackSessionTracker(store playbackRecorder) *playbackSessionTracker {
	return &playbackSessionTracker{
		sessions: make(map[string]*playbackSession),
		window:   playbackSessionWindow,
		store:    store,
		nowFn:    time.Now,
	}
}

// record 注入一次流式请求（displayPath 已解析）。
// durationSecs 为本次流式写出的墙钟时长；rangeStart>0 且量小计一次 seek。
// 会话不立即落库：一直挂着直到超时/超龄/路径切换，由 flush 统一落库，
// 避免每条 Range 请求（首帧、多次 seek）各落一条。
func (t *playbackSessionTracker) record(
	path, provider, contentType string,
	bytesServed, totalBytes int64,
	durationSecs float64,
	completed bool,
	rangeStart int64,
) {
	if t == nil || t.store == nil || strings.TrimSpace(path) == "" || bytesServed <= 0 {
		return
	}
	now := t.nowFn()
	seekCount := 0
	if isSeekLikeRequest(rangeStart, bytesServed) {
		seekCount = 1
	}

	t.mu.Lock()
	// 先落库已超时的会话（含路径切换后残留的旧路径会话）。
	for _, sess := range t.sessions {
		if now.Sub(sess.lastAt) > t.window || now.Sub(sess.startAt) > playbackSessionMaxLifetime {
			t.flushLocked(sess)
		}
	}
	sess := t.sessions[path]
	if sess == nil {
		sess = &playbackSession{
			path:        path,
			provider:    provider,
			contentType: contentType,
			startAt:     now,
			totalBytes:  totalBytes,
		}
		t.sessions[path] = sess
	}
	sess.lastAt = now
	sess.bytesServed += bytesServed
	sess.durationSecs += durationSecs
	sess.seekCount += seekCount
	if completed {
		sess.contentType = contentType
	}
	t.mu.Unlock()
}

// flushLocked 把一条会话写库并删除。调用方需持有 mu。
func (t *playbackSessionTracker) flushLocked(sess *playbackSession) {
	if sess == nil || t.store == nil {
		return
	}
	if sess.bytesServed <= 0 {
		delete(t.sessions, sess.path)
		return
	}
	playedAt := sess.startAt.Unix()
	rec := PlaybackStatsRecord{
		ID:           strconv.FormatInt(sess.startAt.UnixNano(), 10) + "-" + sess.path,
		Path:         sess.path,
		Provider:     sess.provider,
		BytesServed:  sess.bytesServed,
		TotalBytes:   sess.totalBytes,
		DurationSecs: sess.durationSecs,
		PlayedAt:     playedAt,
		Completed:    true,
		ContentType:  sess.contentType,
		SeekCount:    sess.seekCount,
	}
	if err := t.store.AppendPlayback(rec); err != nil {
		log.Errorf("[%s] failed to flush playback session: %v", internal.TagCache, err)
	}
	delete(t.sessions, sess.path)
}

// flushStale 落库所有空闲超过窗口的会话（供定时清理调用）。
func (t *playbackSessionTracker) flushStale(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, sess := range t.sessions {
		if now.Sub(sess.lastAt) > t.window {
			t.flushLocked(sess)
		}
	}
}

// isSeekLikeRequest 判定一次 Range 请求是否为 seek（快进/快退）。
// 起始位置 > 0 且请求体量小 → 定位型预取，而非连续顺序播放段。
func isSeekLikeRequest(rangeStart, bytesServed int64) bool {
	return rangeStart > 0 && bytesServed <= seekRangeHintBytes
}

// rangeStartFromRequest 解析 Range 头里的起始位置（无 Range 返回 0）。
func rangeStartFromRequest(r *http.Request) int64 {
	if r == nil || r.Header == nil {
		return 0
	}
	start, ok := parseRangeStart(r.Header.Get("Range"))
	if !ok {
		return 0
	}
	return start
}

// ensurePlaybackSessionTracker 惰性创建会话聚合器（绑定 localStore）。
func (p *ProxyServer) ensurePlaybackSessionTracker() *playbackSessionTracker {
	if p == nil {
		return nil
	}
	p.playbackSessionOnce.Do(func() {
		p.playbackSession = newPlaybackSessionTracker(p.localStore)
	})
	return p.playbackSession
}

// FlushPlaybackSessions 落库所有进行中的播放会话（进程退出/导出前调用）。
// 导出方法：跨包（顶层 openlistlib 的 ExportEncryptStatsJson）需要调用。
func (p *ProxyServer) FlushPlaybackSessions() {
	if p == nil || p.playbackSession == nil {
		return
	}
	p.playbackSession.flushStale(time.Now().Add(time.Hour))
}
