package google_drive

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/go-resty/resty/v2"
)

type localTransport struct {
	target *url.URL
}

func (tr localTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.URL.Scheme, r.URL.Host = tr.target.Scheme, tr.target.Host
	return http.DefaultTransport.RoundTrip(r)
}

func TestInitAndListCancelHTTPRequest(t *testing.T) {
	for _, operation := range []string{"init", "list", "shortcut", "auth-refresh"} {
		t.Run(operation, func(t *testing.T) {
			started := make(chan struct{})
			stopped := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if operation == "auth-refresh" && r.URL.Path == "/drive/v3/files" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error":{"code":401,"message":"expired"}}`))
					return
				}
				if operation == "shortcut" && r.URL.Path == "/drive/v3/files" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"files":[{"id":"shortcut","mimeType":"application/vnd.google-apps.shortcut","shortcutDetails":{"targetId":"target","targetMimeType":"video/mp4"}}]}`))
					return
				}
				close(started)
				select {
				case <-r.Context().Done():
					close(stopped)
				case <-time.After(3 * time.Second):
				}
			}))
			defer server.Close()
			target, _ := url.Parse(server.URL)
			previous := base.RestyClient
			base.RestyClient = resty.New().SetTransport(localTransport{target})
			defer func() { base.RestyClient = previous }()
			d := &GoogleDrive{Addition: Addition{UseOnlineAPI: true, APIAddress: server.URL, RefreshToken: "old-refresh"}, AccessToken: "old-access"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				if operation == "init" {
					result <- d.Init(ctx)
				} else {
					_, err := d.List(ctx, &model.Object{ID: "root"}, model.ListArgs{})
					result <- err
				}
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("request did not start")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected canceled, got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("operation did not cancel")
			}
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("HTTP request was not canceled")
			}
			if d.AccessToken != "old-access" || d.RefreshToken != "old-refresh" {
				t.Fatal("canceled operation published tokens")
			}
		})
	}
}
