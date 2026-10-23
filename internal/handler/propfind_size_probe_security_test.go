package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestPropfindSizeOnlyForeignLocatorNeverReceivesCallerCredentials(t *testing.T) {
	header, err := encryption.BuildV2Header(encryption.EncTypeAESCTR, 100, bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	body := append(header, make([]byte, 100)...)
	cdn := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, key := range []string{"Authorization", "Cookie", "X-Provider-Secret"} {
			if r.Header.Get(key) != "" {
				t.Errorf("foreign locator received %s", key)
			}
		}
		http.ServeContent(w, r, "raw.bin", time.Time{}, bytes.NewReader(body))
	}))
	defer cdn.Close()
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic caller" {
			t.Error("upstream did not receive caller authorization")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"raw_url": cdn.URL + "/signed", "size": len(body)}})
	}))
	defer upstream.Close()
	ps, file := newPropfindSizeScheduler(t, upstream.URL, 2)
	ps.EnqueueWithSource(file, http.Header{"Authorization": []string{"Basic caller"}, "Cookie": []string{"private-cookie"}, "X-Provider-Secret": []string{"private-provider"}}, int64(len(body)), probeSourcePropfind)
	item := <-ps.queue
	ps.runItem(item)
	if _, hit := ps.fileDAO.GetConfirmedPlayback(item.sizeOnly.identity); !hit {
		t.Fatal("foreign signed locator failed confirmation")
	}
}

func TestPropfindSizeOnlyConfigChangeDuringInspectionCannotPublish(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	header, err := encryption.BuildV2Header(encryption.EncTypeAESCTR, 100, bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	body := append(header, make([]byte, 100)...)
	var origin string
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fs/get" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"raw_url": origin + "/media", "size": len(body)}})
			return
		}
		close(entered)
		<-release
		http.ServeContent(w, r, "raw.bin", time.Time{}, bytes.NewReader(body))
	}))
	defer upstream.Close()
	origin = upstream.URL
	ps, file := newPropfindSizeScheduler(t, origin, 2)
	ps.EnqueueWithSource(file, http.Header{"Authorization": []string{"Basic caller"}}, int64(len(body)), probeSourcePropfind)
	item := <-ps.queue
	done := make(chan struct{})
	go func() { ps.runItem(item); close(done) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("inspection did not start")
	}
	alist := ps.cfg.AlistServerSnapshot()
	alist.PasswdList[0].Password = "changed-during-inspection"
	if err := ps.cfg.UpdateAlistServer(alist); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("inspection did not finish")
	}
	if _, hit := ps.fileDAO.GetConfirmedPlayback(item.sizeOnly.identity); hit {
		t.Fatal("old configuration published after inspection")
	}
}
