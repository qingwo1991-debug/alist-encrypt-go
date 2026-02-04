package encryption

import (
	"io"
	"sync"
)

// baseBufferPool is a shared buffer pool for cipher readers/writers
var baseBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64*1024) // 64KB buffers
		return &buf
	},
}

// GetCipherBuffer gets a buffer from the pool
func GetCipherBuffer() *[]byte {
	return baseBufferPool.Get().(*[]byte)
}

// PutCipherBuffer returns a buffer to the pool
func PutCipherBuffer(buf *[]byte) {
	baseBufferPool.Put(buf)
}

// CipherTransformer defines the transform function for stream ciphers
type CipherTransformer interface {
	Transform(data []byte)
}

// streamReader is a generic cipher reader wrapper
type streamReader struct {
	reader      io.Reader
	transformer CipherTransformer
}

// WrapReader creates a reader that transforms data using the cipher
func WrapReader(r io.Reader, t CipherTransformer) io.Reader {
	return &streamReader{
		reader:      r,
		transformer: t,
	}
}

func (r *streamReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.transformer.Transform(p[:n])
	}
	return n, err
}

// streamWriter is a generic cipher writer wrapper
type streamWriter struct {
	writer      io.Writer
	transformer CipherTransformer
	pool        *sync.Pool
}

// WrapWriter creates a writer that transforms data using the cipher
func WrapWriter(w io.Writer, t CipherTransformer) io.Writer {
	return &streamWriter{
		writer:      w,
		transformer: t,
		pool:        &baseBufferPool,
	}
}

func (w *streamWriter) Write(p []byte) (int, error) {
	// Use buffer pool for small writes
	var encrypted []byte
	if len(p) <= 64*1024 {
		bufPtr := w.pool.Get().(*[]byte)
		defer w.pool.Put(bufPtr)
		encrypted = (*bufPtr)[:len(p)]
	} else {
		encrypted = make([]byte, len(p))
	}
	copy(encrypted, p)
	w.transformer.Transform(encrypted)
	return w.writer.Write(encrypted)
}

// TransformFunc is an adapter to use a function as CipherTransformer
type TransformFunc func(data []byte)

func (f TransformFunc) Transform(data []byte) {
	f(data)
}

// WrapReaderFunc creates a reader using a transform function
func WrapReaderFunc(r io.Reader, transform func(data []byte)) io.Reader {
	return WrapReader(r, TransformFunc(transform))
}

// WrapWriterFunc creates a writer using a transform function
func WrapWriterFunc(w io.Writer, transform func(data []byte)) io.Writer {
	return WrapWriter(w, TransformFunc(transform))
}
