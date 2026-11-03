package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/storage"
)

// StateSucceeded is 2 in github.com/OpenListTeam/tache v0.2.2 (the version
// pinned by mobile/openlist-lib/go.mod), not an inference from progress/status.
// https://github.com/OpenListTeam/tache/blob/v0.2.2/state.go
const filenameTaskSucceeded = 2
const filenameTaskMaxConcurrent = 4
const filenameTaskPollTimeout = 2 * time.Minute
const filenameTaskPollInterval = 2 * time.Second
const filenameTaskResponseLimit = 2 * 1024 * 1024

type filenameUploadTaskRepository interface {
	BindFilenameUploadTask(storage.FilenameUploadTask) error
	GetFilenameUploadTask(origin, id, auth string) (storage.FilenameUploadTask, bool, error)
}

type filenameTaskReservationRepository interface {
	filenameReservationRepository
	GetFilenameReservation(string, string) (storage.FilenameRecord, bool, error)
}

type filenameTaskInfo struct {
	ID    string `json:"id"`
	State *int   `json:"state"`
}

// A successful As-Task request may actually have been synchronous. Only a
// non-empty task.id establishes an accepted task; malformed receipts fail closed.
func filenameAcceptedTaskID(body []byte) (string, error) {
	var response struct {
		Code int `json:"code"`
		Data *struct {
			Task *struct {
				ID string `json:"id"`
			} `json:"task"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}
	if response.Code != 200 {
		return "", fmt.Errorf("upload response code %d", response.Code)
	}
	if response.Data == nil || response.Data.Task == nil {
		return "", nil
	}
	id := response.Data.Task.ID
	if id == "" || strings.TrimSpace(id) != id {
		return "", fmt.Errorf("invalid upload task ID")
	}
	return id, nil
}

// Persist only a digest; the credentials used by detached polling live here in
// memory and expire with the bounded worker. Never borrow configured admin auth.
func filenameTaskCredentials(src http.Header) http.Header {
	h := make(http.Header)
	for _, key := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		h[key] = append([]string(nil), src.Values(key)...)
	}
	return h
}

func (h *AlistHandler) acquireFilenameTask(key string) bool {
	h.filenameTaskMu.Lock()
	defer h.filenameTaskMu.Unlock()
	if h.filenameTaskSem == nil {
		h.filenameTaskSem = make(chan struct{}, filenameTaskMaxConcurrent)
	}
	if h.filenameTaskPending == nil {
		h.filenameTaskPending = make(map[string]bool)
	}
	if h.filenameTaskPending[key] {
		return false
	}
	select {
	case h.filenameTaskSem <- struct{}{}:
		h.filenameTaskPending[key] = true
		return true
	default:
		return false
	}
}
func (h *AlistHandler) releaseFilenameTask(key string) {
	h.filenameTaskMu.Lock()
	delete(h.filenameTaskPending, key)
	<-h.filenameTaskSem
	h.filenameTaskMu.Unlock()
}
func filenameTaskWorkKey(origin, id, auth string) string {
	return filenameScopeDigest(origin, id, auth)
}

func (h *AlistHandler) pollFilenameUploadTask(receipt storage.FilenameUploadTask, credentials http.Header) {
	key := filenameTaskWorkKey(receipt.Origin, receipt.TaskID, receipt.AuthScope)
	if !h.acquireFilenameTask(key) {
		return
	}
	if !h.startDirSyncWork(func(parent context.Context) {
		defer h.releaseFilenameTask(key)
		ctx, cancel := context.WithTimeout(parent, filenameTaskPollTimeout)
		defer cancel()
		ticker := time.NewTicker(filenameTaskPollInterval)
		defer ticker.Stop()
		for {
			// Use the original caller's credentials, not the canceled upload request.
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://encrypt.local/api/task/upload/info?tid="+url.QueryEscape(receipt.TaskID), nil)
			if err != nil {
				return
			}
			req.Header = credentials.Clone()
			resp, err := h.filenameTaskUpstream(req, receipt.Origin)
			if err == nil {
				body, readErr := io.ReadAll(io.LimitReader(resp.Body, filenameTaskResponseLimit+1))
				resp.Body.Close()
				if readErr == nil && len(body) <= filenameTaskResponseLimit && resp.StatusCode == http.StatusOK {
					for _, task := range filenameTaskResults(req, body) {
						if task.ID == receipt.TaskID && task.State != nil && *task.State == filenameTaskSucceeded {
							if h.reconcileFilenameTask(req, receipt.Origin, task) == nil {
								return
							}
						}
					}
				}
			}
			// Failed/canceled/errored remains pending: upstream retry reuses the ID.
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}) {
		h.releaseFilenameTask(key)
	}
}

func (h *AlistHandler) filenameTaskUpstream(r *http.Request, origin string) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	// Response bodies must retain the context until closed by the caller.
	target := httputil.BuildTargetURLWithQuery(origin, r.URL.Path, r.URL.RawQuery)
	req, err := http.NewRequestWithContext(ctx, r.Method, target, r.Body)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header = filenameTaskCredentials(r.Header)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	client := *h.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &filenameTaskResponseBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type filenameTaskResponseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *filenameTaskResponseBody) Close() error { defer b.cancel(); return b.ReadCloser.Close() }

func filenameTaskResults(r *http.Request, body []byte) []filenameTaskInfo {
	var envelope struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Code != 200 {
		return nil
	}
	if r.URL.Path == "/api/task/upload/info" {
		var task filenameTaskInfo
		if json.Unmarshal(envelope.Data, &task) != nil || task.ID == "" || task.ID != r.URL.Query().Get("tid") {
			return nil
		}
		return []filenameTaskInfo{task}
	}
	var tasks []filenameTaskInfo
	if json.Unmarshal(envelope.Data, &tasks) != nil {
		return nil
	}
	return tasks
}

// Task query routes remain upstream-authenticated passthroughs. Local recovery
// cannot change the upstream response, and mutation/retry routes stay catch-all.
func (h *AlistHandler) HandleUploadTasks(w http.ResponseWriter, r *http.Request) {
	origin := h.cfg.GetAlistURL()
	resp, err := h.filenameTaskUpstream(r, origin)
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, values := range resp.Header {
		w.Header()[k] = append([]string(nil), values...)
	}
	w.WriteHeader(resp.StatusCode)
	// Forward arbitrary-sized responses intact, but retain only a bounded prefix
	// for optional reconciliation. Oversized/malformed data is never interpreted.
	capture := &filenameTaskCapture{}
	_, err = io.Copy(io.MultiWriter(w, capture), resp.Body)
	if err != nil || capture.overflow || resp.StatusCode != http.StatusOK {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	auth := filenameRequestScope(r)
	// Reconcile a bounded budget of only locally-tracked successful tasks. Cheap
	// receipt filtering happens before the budget so unrelated/failed tasks on a
	// done list cannot starve a real receipt that appears later in the response.
	taskRepo, hasTaskRepo := h.fileDAO.(filenameUploadTaskRepository)
	reconcileRepo, hasReconcileRepo := h.fileDAO.(filenameTaskReservationRepository)
	tasks := filenameTaskResults(r, capture.body)
	// Reconcile pending receipts before already-complete ones. Complete items are
	// now cheap no-ops, but prioritizing pending work means a large or slow set of
	// completed tasks cannot starve a pending receipt within the bounded budget.
	reconcile := func(pendingOnly bool) {
		for _, task := range tasks {
			if task.State == nil || *task.State != filenameTaskSucceeded || !hasTaskRepo {
				continue
			}
			receipt, found, err := taskRepo.GetFilenameUploadTask(origin, task.ID, auth)
			if err != nil || !found {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			if pendingOnly && hasReconcileRepo {
				rec, _, rerr := reconcileRepo.GetFilenameReservation(origin, receipt.EncryptedPath)
				if rerr == nil && rec.Status == storage.FilenameComplete {
					continue
				}
			}
			key := filenameTaskWorkKey(origin, task.ID, auth)
			if !h.acquireFilenameTask(key) {
				continue
			}
			_ = h.reconcileFilenameTask(r.WithContext(ctx), origin, task)
			h.releaseFilenameTask(key)
		}
	}
	reconcile(true)
	reconcile(false)
}

type filenameTaskCapture struct {
	body     []byte
	overflow bool
}

func (c *filenameTaskCapture) Write(p []byte) (int, error) {
	if !c.overflow && len(c.body)+len(p) <= filenameTaskResponseLimit {
		c.body = append(c.body, p...)
	} else {
		c.overflow = true
		c.body = nil
	}
	return len(p), nil
}

func (h *AlistHandler) reconcileFilenameTask(r *http.Request, origin string, task filenameTaskInfo) error {
	if task.State == nil || *task.State != filenameTaskSucceeded || task.ID == "" || h.cfg.GetAlistURL() != origin {
		return fmt.Errorf("task not eligible")
	}
	tasks, ok := h.fileDAO.(filenameUploadTaskRepository)
	if !ok {
		return fmt.Errorf("task store unavailable")
	}
	repo, ok := h.fileDAO.(filenameTaskReservationRepository)
	if !ok {
		return fmt.Errorf("reservation store unavailable")
	}
	auth := filenameRequestScope(r)
	receipt, found, err := tasks.GetFilenameUploadTask(origin, task.ID, auth)
	if err != nil {
		return err
	}
	if !found || receipt.Origin != origin || receipt.TaskID != task.ID || receipt.AuthScope != auth {
		return fmt.Errorf("task receipt scope mismatch")
	}
	rec, found, err := repo.GetFilenameReservation(origin, receipt.EncryptedPath)
	if err != nil {
		return err
	}
	if !found || rec.Origin != origin || rec.EncryptedPath != receipt.EncryptedPath || rec.Token != receipt.Token || rec.AuthScope != auth || rec.RuleFingerprint != receipt.RuleFingerprint || (rec.Status != storage.FilenamePending && rec.Status != storage.FilenameComplete) {
		return fmt.Errorf("task reservation mismatch")
	}
	if rec.Status == storage.FilenameComplete {
		// Already finalized: no re-verification or mapping rewrite is needed.
		// This keeps repeated queries cheap so they cannot starve pending
		// receipts that share the bounded reconciliation budget.
		return nil
	}
	info, found := h.passwdDAO.PathFindPasswd(rec.OriginalPath)
	if !found || info == nil || !info.EncName || filenameRuleFingerprint(info) != rec.RuleFingerprint {
		return fmt.Errorf("task encryption rule changed")
	}
	// Explicit API listing is essential: this is a task URL, not /api/fs/put,
	// and filenameRemoteHead would otherwise incorrectly attempt DAV auth.
	status, size, err := filenameRemoteAPIList(r, origin, rec.EncryptedPath, h.httpClient)
	if err != nil {
		return err
	}
	if status != http.StatusOK || size != rec.CiphertextSize {
		return fmt.Errorf("task destination not yet verified")
	}
	// CAS checks the receipt's token again inside the durable transaction.
	if err := repo.FinishFilenameReservation(origin, rec.EncryptedPath, receipt.Token, storage.FilenameComplete); err != nil {
		return err
	}
	h.fileDAO.SetEncPathMapping(rec.OriginalPath, rec.EncryptedPath)
	return nil
}
