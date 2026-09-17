package encrypt

import (
	"io"
	"time"
)

// firstByteTimingWriter is used only at the final decrypted copy boundary. It
// performs one clock read/log attempt per stream, not per chunk, and never
// records a path, URL, credential, or the client's raw Range header.
type firstByteTimingWriter struct {
	dst      io.Writer
	proxy    *ProxyServer
	started  time.Time
	hasRange bool
	recorded bool
}

func (w *firstByteTimingWriter) Write(b []byte) (int, error) {
	n, err := w.dst.Write(b)
	if n > 0 && !w.recorded {
		w.recorded = true
		w.proxy.debugf("play", "stream first_byte_ms=%d range=%t", time.Since(w.started).Milliseconds(), w.hasRange)
	}
	return n, err
}
