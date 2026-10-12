package onedrive

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/go-resty/resty/v2"
)

func TestInitAndListCancelHTTPRequest(t *testing.T) {
	for _, operation := range []string{"init", "list", "next-page", "reference", "auth-refresh"} {
		t.Run(operation, func(t *testing.T) {
			started := make(chan struct{})
			stopped := make(chan struct{})
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if operation == "auth-refresh" && r.URL.Path != "/" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error":{"code":"InvalidAuthenticationToken","message":"expired"}}`))
					return
				}
				if operation == "next-page" && r.URL.Path != "/next" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"value":[],"@odata.nextLink":"http://` + r.Host + `/next"}`))
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
			previous := base.RestyClient
			base.RestyClient = resty.New()
			defer func() { base.RestyClient = previous }()
			const region = "context-test"
			onedriveHostMap[region] = Host{Api: server.URL, Oauth: server.URL}
			defer delete(onedriveHostMap, region)
			d := &Onedrive{Addition: Addition{Region: region, UseOnlineAPI: true, APIAddress: server.URL, RefreshToken: "old-refresh"}, AccessToken: "old-access"}
			if operation == "reference" {
				d.ref = &Onedrive{AccessToken: "reference-token"}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				if operation == "init" {
					result <- d.Init(ctx)
				} else {
					_, err := d.List(ctx, &model.Object{Path: "/"}, model.ListArgs{})
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
			if operation == "init" && requests.Load() != 1 {
				t.Fatalf("canceled refresh retried: %d requests", requests.Load())
			}
			if d.AccessToken != "old-access" || d.RefreshToken != "old-refresh" {
				t.Fatal("canceled operation published tokens")
			}
		})
	}
}
