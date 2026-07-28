package handler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestResolveWithEarlyTerminationDoesNotTreatInternalCancelAsCallerCancel(t *testing.T) {
	const iterations = 256

	for i := 0; i < iterations; i++ {
		resolver := &FileSizeResolver{
			semaphore: make(chan struct{}, 2),
			client: &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
				switch req.Method {
				case http.MethodHead:
					<-req.Context().Done()
					return nil, req.Context().Err()
				case http.MethodGet:
					return &http.Response{
						StatusCode: http.StatusPartialContent,
						Header: http.Header{
							"Content-Range": []string{"bytes 0-0/1048576"},
							"Content-Type":  []string{"video/mp4"},
						},
						Body:    io.NopCloser(strings.NewReader("x")),
						Request: req,
					}, nil
				default:
					t.Fatalf("unexpected method %q", req.Method)
					return nil, errors.New("unexpected method")
				}
			})},
			maxRedirects: 1,
		}

		result := resolver.resolveWithEarlyTermination(context.Background(), FileItem{
			DisplayPath: "/movie.mp4",
			TargetURL:   "https://example.test/movie.mp4",
			FileName:    "movie.mp4",
		}, nil)
		if result.Error != nil {
			t.Fatalf("iteration %d: got error %v, want the winning Range result", i, result.Error)
		}
		if result.Source != SourceRange || result.Size != 1048576 {
			t.Fatalf("iteration %d: got source=%q size=%d, want source=%q size=%d", i, result.Source, result.Size, SourceRange, 1048576)
		}
	}
}

func TestResolveWithEarlyTerminationPreservesCallerCancellation(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	done := make(chan struct{}, 2)

	resolver := &FileSizeResolver{
		semaphore: make(chan struct{}, 2),
		client: &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
			started <- struct{}{}
			<-req.Context().Done()
			<-release
			done <- struct{}{}
			return nil, req.Context().Err()
		})},
		maxRedirects: 1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan SizeResult, 1)
	go func() {
		resultCh <- resolver.resolveWithEarlyTermination(ctx, FileItem{
			DisplayPath: "/movie.mp4",
			TargetURL:   "https://example.test/movie.mp4",
			FileName:    "movie.mp4",
		}, nil)
	}()

	<-started
	<-started
	cancel()

	select {
	case result := <-resultCh:
		if !errors.Is(result.Error, context.Canceled) {
			t.Fatalf("got error %v, want context.Canceled", result.Error)
		}
	case <-time.After(time.Second):
		t.Fatal("resolver did not return after caller cancellation")
	}

	close(release)
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("probe did not stop after caller cancellation")
		}
	}
}
