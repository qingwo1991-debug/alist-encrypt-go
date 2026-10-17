package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/gin-gonic/gin"
)

const backupMaxBytes int64 = 1 << 30
const backupTimeout = 30 * time.Second
const backupHistory = 64

var errBackupBusy = errors.New("backup busy")
var errBackupStopped = errors.New("backup stopped")

type backupStatus struct {
	ID               string                    `json:"id"`
	State            string                    `json:"state"`
	CreatedAt        time.Time                 `json:"created_at"`
	FinishedAt       *time.Time                `json:"finished_at,omitempty"`
	CancelRequested  bool                      `json:"cancel_requested"`
	Components       []string                  `json:"components"`
	Excluded         []string                  `json:"excluded"`
	Scope            string                    `json:"scope"`
	FullRestoreReady bool                      `json:"full_restore_ready"`
	Version          string                    `json:"version"`
	SourceCommit     string                    `json:"source_commit,omitempty"`
	Manifest         *storage.SnapshotManifest `json:"manifest,omitempty"`
	Error            string                    `json:"error,omitempty"`
}
type backupJob struct {
	status backupStatus
	cancel context.CancelFunc
}
type backupRunner func(context.Context, string, string, storage.SnapshotOptions) (storage.SnapshotManifest, error)

// The lock serializes admission, sealing and WG.Add: Wait cannot race admission.
// A cancel only signals; the actual runner return releases the single slot.
type backupOwner struct {
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	wg        sync.WaitGroup
	sealed    bool
	active    *backupJob
	jobs      map[string]*backupJob
	order     []string
	directory string
	commit    string
	run       backupRunner
}

func newBackupOwner(store *storage.Store, dataDir string) (*backupOwner, error) {
	directory := filepath.Join(dataDir, "backups")
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	// Never follow an existing symlink or silently adopt a public directory.
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("backup directory must be private")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &backupOwner{ctx: ctx, cancel: cancel, directory: directory, commit: backupBuildCommit(), jobs: make(map[string]*backupJob), run: store.CreateSnapshot}, nil
}
func backupBuildCommit() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && (len(setting.Value) == 40 || len(setting.Value) == 64) {
				if _, err := hex.DecodeString(setting.Value); err == nil {
					return setting.Value
				}
			}
		}
	}
	return "" // Unknown provenance is not the worktree's current HEAD.
}
func (o *backupOwner) create(maxBytes int64, timeout time.Duration) (backupStatus, error) {
	if maxBytes <= 0 || maxBytes > backupMaxBytes || timeout <= 0 || timeout > backupTimeout {
		return backupStatus{}, errors.New("invalid backup bounds")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sealed {
		return backupStatus{}, errBackupStopped
	}
	if o.active != nil {
		return backupStatus{}, errBackupBusy
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return backupStatus{}, err
	}
	id := hex.EncodeToString(random[:])
	if o.jobs[id] != nil {
		return backupStatus{}, errors.New("backup id collision")
	}
	ctx, cancel := context.WithTimeout(o.ctx, timeout)
	job := &backupJob{cancel: cancel, status: backupStatus{ID: id, State: "running", CreatedAt: time.Now().UTC(), Components: []string{"rootBolt"}, Excluded: []string{"external-runtime-config", "mysql", "sqlite"}, Scope: "component_only", Version: config.Version, SourceCommit: o.commit}}
	if len(o.order) == backupHistory {
		delete(o.jobs, o.order[0])
		o.order = o.order[1:]
	}
	o.jobs[id] = job
	o.order = append(o.order, id)
	o.active = job
	o.wg.Add(1)
	go o.work(ctx, job, storage.SnapshotOptions{MaxBytes: maxBytes, Commit: o.commit})
	return job.status, nil
}
func (o *backupOwner) work(ctx context.Context, job *backupJob, options storage.SnapshotOptions) {
	defer o.wg.Done()
	manifest, err := o.run(ctx, o.directory, job.status.ID+".tar", options)
	job.cancel()
	o.mu.Lock()
	defer o.mu.Unlock()
	finished := time.Now().UTC()
	job.status.FinishedAt = &finished
	job.status.State = "succeeded"
	if err != nil {
		job.status.State = "failed"
		job.status.Error = "snapshot_failed"
		if errors.Is(err, context.Canceled) {
			job.status.State = "canceled"
			job.status.Error = "canceled"
		}
		if errors.Is(err, context.DeadlineExceeded) {
			job.status.State = "timed_out"
			job.status.Error = "deadline_exceeded"
		}
	} else {
		job.status.Manifest = &manifest
	}
	o.active = nil
}
func (o *backupOwner) status(id string, cancel bool) (backupStatus, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	job, ok := o.jobs[id]
	if !ok {
		return backupStatus{}, false
	}
	if cancel && job == o.active {
		job.status.CancelRequested = true
		job.cancel()
	}
	return job.status, true
}
func (o *backupOwner) seal() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sealed = true
	if o.active != nil {
		o.active.status.CancelRequested = true
	}
	o.cancel()
}
func (o *backupOwner) wait() { o.wg.Wait() }

// Current repository management JWTs have username, not role claims. All existing
// management accounts share this capability; no new RBAC or provider auth claim.
func (s *Server) backupManagementAuth() gin.HandlerFunc {
	validator := auth.NewJWTAuth(s.cfg.JWTSecret, time.Hour)
	return func(c *gin.Context) {
		token, _ := c.Get("user_token")
		text, _ := token.(string)
		claims, err := validator.ValidateToken(text)
		if err != nil || claims.Username == "" || s.userDAO == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		user, err := s.userDAO.Get(claims.Username)
		if err != nil || user.Username != claims.Username {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}
func (s *Server) registerBackupRoutes(protected *gin.RouterGroup) {
	group := protected.Group("/admin/backups", s.backupManagementAuth())
	group.POST("", func(c *gin.Context) {
		var request *struct {
			MaxBytes       *int64 `json:"max_bytes"`
			TimeoutSeconds *int64 `json:"timeout_seconds"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 1024))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&request)
		if (err != nil && err != io.EOF) || (err == nil && request == nil) {
			c.JSON(400, gin.H{"error": "invalid_request"})
			return
		}
		// Only an empty body or one JSON object is supported.
		if err == nil {
			var extra any
			if decoder.Decode(&extra) != io.EOF {
				c.JSON(400, gin.H{"error": "invalid_request"})
				return
			}
		}
		maxBytes, seconds := backupMaxBytes, int64(30)
		if request != nil {
			if request.MaxBytes != nil {
				maxBytes = *request.MaxBytes
			}
			if request.TimeoutSeconds != nil {
				seconds = *request.TimeoutSeconds
			}
		}
		if maxBytes <= 0 || maxBytes > backupMaxBytes || seconds <= 0 || seconds > 30 {
			c.JSON(400, gin.H{"error": "invalid_bounds"})
			return
		}
		status, err := s.backups.create(maxBytes, time.Duration(seconds)*time.Second)
		if err != nil {
			code := 500
			message := "backup_failed"
			if errors.Is(err, errBackupBusy) {
				code = 409
				message = "backup_busy"
			}
			if errors.Is(err, errBackupStopped) {
				code = 503
				message = "backup_stopped"
			}
			c.JSON(code, gin.H{"error": message})
			return
		}
		c.JSON(http.StatusAccepted, status)
	})
	get := func(cancel bool) gin.HandlerFunc {
		return func(c *gin.Context) {
			status, ok := s.backups.status(c.Param("id"), cancel)
			if !ok {
				c.JSON(404, gin.H{"error": "not_found"})
				return
			}
			c.JSON(200, status)
		}
	}
	group.GET("/:id", get(false))
	group.POST("/:id/cancel", get(true))
}
