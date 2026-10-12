package handler

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestV3FollowupAuthFailureTriesNextProbeVariant(t *testing.T) {
	var container bytes.Buffer
	writer, err := encryption.NewV3Writer(&container, "pw", 73)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte("abc"), 79)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, failedRange := range []string{"bytes=32-47", fmt.Sprintf("bytes=%d-%d", container.Len()-16, container.Len()-1)} {
		t.Run(failedRange, func(t *testing.T) {
			var rejected, authenticated int
			srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Range") == failedRange && r.Header.Get("Authorization") != "Bearer good" {
					rejected++
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if r.Header.Get("Authorization") == "Bearer good" {
					authenticated++
				}
				var start, end int
				if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil || start < 0 || end < start || end >= container.Len() {
					http.Error(w, "bad range", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, container.Len()))
				w.Header().Set("Content-Length", strconv.Itoa(end-start+1))
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(container.Bytes()[start : end+1])
			}))
			defer srv.Close()
			cfg := config.DefaultConfig()
			sp := proxy.NewStreamProxy(cfg)
			var statuses []int
			got := probeCandidateWithAuth(nil, srv.URL, []http.Header{{"Authorization": {"Bearer bad"}}, {"Authorization": {"Bearer good"}}}, func(h http.Header) proxy.ContentInspectionResult {
				result := sp.InspectEncryptedContentResult(context.Background(), srv.URL, h, &config.PasswdInfo{Enable: true, EncType: "aesctr"}, 0)
				statuses = append(statuses, result.StatusCode)
				return result
			})
			if !got.Confirmed || !got.Meta.IsV3() || got.Meta.PlainSize != 237 || rejected != 1 || authenticated != 3 || len(statuses) != 2 || statuses[0] != http.StatusForbidden {
				t.Fatalf("auth retry failed: result=%+v rejected=%d authenticated=%d statuses=%v range=%s", got, rejected, authenticated, statuses, strings.TrimSpace(failedRange))
			}
		})
	}
}
