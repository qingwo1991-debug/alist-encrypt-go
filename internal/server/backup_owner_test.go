package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/gin-gonic/gin"
)

func backupFixture(t *testing.T) (*storage.Store, *backupOwner) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newBackupOwner(store, dir)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.seal(); owner.wait(); _ = store.Close() })
	return store, owner
}
func TestBackupOwnerCancelRetainsSlotAndShutdownJoins(t *testing.T) {
	store, o := backupFixture(t)
	entered, signal, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	o.run = func(ctx context.Context, dir, name string, opts storage.SnapshotOptions) (storage.SnapshotManifest, error) {
		close(entered)
		<-ctx.Done()
		close(signal)
		<-release
		// A real store access here proves shutdown did not close it while blocked.
		if err := store.SetJSON(storage.BucketConfig, "worker-return", true); err != nil {
			t.Error(err)
		}
		return storage.SnapshotManifest{}, ctx.Err()
	}
	status, err := o.create(backupMaxBytes, backupTimeout)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	canceled, ok := o.status(status.ID, true)
	if !ok || !canceled.CancelRequested || canceled.State != "running" {
		t.Fatal(canceled)
	}
	<-signal
	if _, err = o.create(backupMaxBytes, backupTimeout); !errors.Is(err, errBackupBusy) {
		t.Fatal(err)
	}
	httpStopped := make(chan struct{})
	httpServer := &http.Server{}
	httpServer.RegisterOnShutdown(func() { close(httpStopped) })
	s := &Server{cfg: &config.Config{}, store: store, backups: o, httpServer: httpServer}
	stopped := make(chan error, 1)
	go func() { stopped <- s.Shutdown(context.Background()) }()
	<-httpStopped
	if _, err = o.create(backupMaxBytes, backupTimeout); !errors.Is(err, errBackupStopped) {
		t.Fatal("owner not sealed before HTTP shutdown", err)
	}
	// The HTTP shutdown callback ran, but actual worker return still owns the slot.
	select {
	case <-stopped:
		t.Fatal("shutdown abandoned runner")
	default:
	}
	close(release)
	if err = <-stopped; err != nil {
		t.Fatal(err)
	}
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = o.create(backupMaxBytes, backupTimeout); !errors.Is(err, errBackupStopped) {
		t.Fatal(err)
	}
	final, _ := o.status(status.ID, false)
	if final.State != "canceled" || final.FinishedAt == nil {
		t.Fatal(final)
	}
}
func TestBackupOwnerRealArtifactPrivatePreviousGood(t *testing.T) {
	store, o := backupFixture(t)
	if err := store.SetJSON(storage.BucketConfig, "secret", "original-name/token"); err != nil {
		t.Fatal(err)
	}
	first, err := o.create(backupMaxBytes, backupTimeout)
	if err != nil {
		t.Fatal(err)
	}
	o.wait()
	final, _ := o.status(first.ID, false)
	if final.State != "succeeded" || final.Manifest == nil {
		t.Fatal(final)
	}
	path := filepath.Join(o.directory, first.ID+".tar")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("artifact: %v %v", info, err)
	}
	if err = storage.ValidateSnapshotBundle(context.Background(), path, backupMaxBytes); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := o.create(1, backupTimeout)
	if err != nil {
		t.Fatal(err)
	}
	o.wait()
	failure, _ := o.status(failed.ID, false)
	if failure.State != "failed" {
		t.Fatal(failure)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("previous good changed", err)
	}
	encoded, _ := json.Marshal(final)
	if strings.Contains(string(encoded), o.directory) || strings.Contains(string(encoded), "original-name") || strings.Contains(string(encoded), "token") {
		t.Fatal(string(encoded))
	}
	if final.Scope != "component_only" || final.FullRestoreReady || strings.Join(final.Components, ",") != "rootBolt" {
		t.Fatal(final)
	}
}
func TestBackupOwnerBoundsHistoryAndPrivateDirectory(t *testing.T) {
	_, o := backupFixture(t)
	for _, b := range []int64{0, -1, backupMaxBytes + 1} {
		if _, err := o.create(b, backupTimeout); err == nil {
			t.Fatal("accepted bounds")
		}
	}
	for _, d := range []time.Duration{0, -1, backupTimeout + 1} {
		if _, err := o.create(backupMaxBytes, d); err == nil {
			t.Fatal("accepted timeout")
		}
	}
	o.run = func(context.Context, string, string, storage.SnapshotOptions) (storage.SnapshotManifest, error) {
		return storage.SnapshotManifest{}, errors.New("private/path")
	}
	var oldest string
	for i := 0; i < backupHistory+3; i++ {
		job, err := o.create(1, backupTimeout)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			oldest = job.ID
		}
		o.wait()
	}
	if len(o.jobs) != backupHistory || len(o.order) != backupHistory {
		t.Fatal("unbounded history")
	}
	if _, ok := o.status(oldest, false); ok {
		t.Fatal("old job retained")
	}
	dir := t.TempDir()
	if err := os.Symlink(o.directory, filepath.Join(dir, "backups")); err != nil {
		t.Fatal(err)
	}
	if _, err := newBackupOwner(nil, dir); err == nil {
		t.Fatal("adopted symlink")
	}
}
func TestBackupAPIMangagementJWTBoundsBusyAndCancel(t *testing.T) {
	store, o := backupFixture(t)
	if err := store.SetJSON(storage.BucketUsers, "operator", dao.User{Username: "operator", PasswordHash: "not-used-by-JWT"}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: "real-test-secret", JWTExpire: 1}
	s := &Server{cfg: cfg, store: store, userDAO: dao.NewUserDAO(store), backups: o}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	protected := r.Group("/enc-api", AuthMiddleware(cfg.JWTSecret, 1))
	s.registerBackupRoutes(protected)
	jwt := auth.NewJWTAuth(cfg.JWTSecret, time.Hour)
	token, err := jwt.GenerateToken("operator")
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		result := httptest.NewRecorder()
		r.ServeHTTP(result, req)
		return result
	}
	for _, path := range []string{"/enc-api/admin/backups", "/enc-api/admin/backups/unknown", "/enc-api/admin/backups/unknown/cancel"} {
		method := "POST"
		if strings.HasSuffix(path, "unknown") {
			method = "GET"
		}
		if got := request(method, path, "", "fake"); got.Code != 401 || strings.Contains(got.Body.String(), "unknown") {
			t.Fatal(got)
		}
	}
	missing, _ := jwt.GenerateToken("deleted")
	if got := request("POST", "/enc-api/admin/backups", "", missing); got.Code != 401 {
		t.Fatal(got)
	}
	for _, body := range []string{`{"filename":"x"}`, `{"path":"/tmp/x"}`, `{"max_bytes":0}`, `{"timeout_seconds":31}`, `{"max_bytes":1073741825}`, `{} {}`} {
		if got := request("POST", "/enc-api/admin/backups", body, token); got.Code != 400 {
			t.Fatal(body, got)
		}
	}
	entered, release := make(chan struct{}), make(chan struct{})
	o.run = func(ctx context.Context, _ string, _ string, _ storage.SnapshotOptions) (storage.SnapshotManifest, error) {
		close(entered)
		<-release
		return storage.SnapshotManifest{}, ctx.Err()
	}
	got := request("POST", "/enc-api/admin/backups", `{}`, token)
	if got.Code != http.StatusAccepted {
		t.Fatal(got)
	}
	var job backupStatus
	if err = json.Unmarshal(got.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	<-entered
	if got = request("POST", "/enc-api/admin/backups", `{}`, token); got.Code != 409 {
		t.Fatal(got)
	}
	if got = request("POST", "/enc-api/admin/backups/"+job.ID+"/cancel", "", token); got.Code != 200 {
		t.Fatal(got)
	}
	if got = request("GET", "/enc-api/admin/backups/not-a-known-server-id", "", token); got.Code != 404 {
		t.Fatal(got)
	}
	close(release)
	o.wait()
	got = request("GET", "/enc-api/admin/backups/"+job.ID, "", token)
	if got.Code != 200 || !strings.Contains(got.Body.String(), `"state":"canceled"`) {
		t.Fatal(got)
	}
}
