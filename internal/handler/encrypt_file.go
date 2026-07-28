package handler

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/rs/zerolog/log"
)

// EncryptTask represents a single file encryption/decryption task.
type EncryptTask struct {
	ID         string    `json:"id"`
	Operation  string    `json:"operation"` // "enc" or "dec"
	EncType    string    `json:"encType"`
	SrcPath    string    `json:"srcPath"`
	DstPath    string    `json:"dstPath"`
	EncName    bool      `json:"encName"`
	TotalFiles int       `json:"totalFiles"`
	DoneFiles  int       `json:"doneFiles"`
	TotalBytes int64     `json:"totalBytes"`
	DoneBytes  int64     `json:"doneBytes"`
	Status     string    `json:"status"` // "running", "done", "error"
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	mu         sync.RWMutex
	cancel     chan struct{}
}

// EncryptTaskView is an immutable snapshot used by status APIs. Keeping API
// serialization separate from the live task prevents races with the worker.
type EncryptTaskView struct {
	ID         string    `json:"id"`
	Operation  string    `json:"operation"`
	EncType    string    `json:"encType"`
	SrcPath    string    `json:"srcPath"`
	DstPath    string    `json:"dstPath"`
	EncName    bool      `json:"encName"`
	TotalFiles int       `json:"totalFiles"`
	DoneFiles  int       `json:"doneFiles"`
	TotalBytes int64     `json:"totalBytes"`
	DoneBytes  int64     `json:"doneBytes"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

func (t *EncryptTask) snapshot() EncryptTaskView {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return EncryptTaskView{
		ID:         t.ID,
		Operation:  t.Operation,
		EncType:    t.EncType,
		SrcPath:    t.SrcPath,
		DstPath:    t.DstPath,
		EncName:    t.EncName,
		TotalFiles: t.TotalFiles,
		DoneFiles:  t.DoneFiles,
		TotalBytes: t.TotalBytes,
		DoneBytes:  t.DoneBytes,
		Status:     t.Status,
		Error:      t.Error,
		CreatedAt:  t.CreatedAt,
		UpdatedAt:  t.UpdatedAt,
	}
}

// EncryptTaskStore manages encrypt/decrypt tasks.
type EncryptTaskStore struct {
	mu    sync.RWMutex
	tasks map[string]*EncryptTask
}

var encryptTaskStore = &EncryptTaskStore{
	tasks: make(map[string]*EncryptTask),
}

func (s *EncryptTaskStore) Add(t *EncryptTask) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks[t.ID] = t
}

func (s *EncryptTaskStore) Get(id string) *EncryptTask {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tasks[id]
}

func (s *EncryptTaskStore) List() []*EncryptTask {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*EncryptTask, 0, len(s.tasks))
	for _, t := range s.tasks {
		result = append(result, t)
	}
	return result
}

func (s *EncryptTaskStore) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tasks, id)
}

func generateTaskID() string {
	hash := md5.Sum([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(hash[:])[:16]
}

// HandleEncryptFile starts a background encryption/decryption task on local files.
func HandleEncryptFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password  string `json:"password"`
		EncType   string `json:"encType"`
		Operation string `json:"operation"`  // "enc" or "dec"
		SrcPath   string `json:"folderPath"` // match old API field name
		DstPath   string `json:"outPath"`
		EncName   bool   `json:"encName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondAPIError(w, 500, "Invalid request")
		return
	}

	if req.Password == "" || req.SrcPath == "" || req.Operation == "" {
		RespondAPIError(w, 500, "Missing required fields: password, folderPath, operation")
		return
	}

	if req.Operation != "enc" && req.Operation != "dec" {
		RespondAPIError(w, 500, "operation must be 'enc' or 'dec'")
		return
	}

	if req.EncType == "" {
		req.EncType = "aesctr"
	}

	info, err := os.Stat(req.SrcPath)
	if err != nil || !info.IsDir() {
		RespondAPIError(w, 500, "Source path does not exist or is not a directory")
		return
	}

	if req.DstPath == "" {
		req.DstPath = filepath.Join(os.TempDir(), "encrypt_output", fmt.Sprintf("%d", time.Now().Unix()))
	}

	if err := os.MkdirAll(req.DstPath, 0755); err != nil {
		RespondAPIError(w, 500, "Cannot create output directory: "+err.Error())
		return
	}

	// Count files and total bytes first
	var files []string
	var totalBytes int64
	if err := filepath.WalkDir(req.SrcPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() == 0 {
			return nil
		}
		files = append(files, path)
		totalBytes += info.Size()
		return nil
	}); err != nil {
		RespondAPIError(w, 500, "Cannot scan source directory: "+err.Error())
		return
	}

	if len(files) == 0 {
		RespondAPIError(w, 200, "No files to process")
		return
	}
	if len(files) > 10000 {
		RespondAPIError(w, 500, "Too many files, exceeding 10000")
		return
	}

	task := &EncryptTask{
		ID:         generateTaskID(),
		Operation:  req.Operation,
		EncType:    req.EncType,
		SrcPath:    req.SrcPath,
		DstPath:    req.DstPath,
		EncName:    req.EncName,
		TotalFiles: len(files),
		TotalBytes: totalBytes,
		Status:     "running",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		cancel:     make(chan struct{}),
	}

	encryptTaskStore.Add(task)

	log.Info().Str("task_id", task.ID).Str("operation", req.Operation).
		Str("src", req.SrcPath).Str("dst", req.DstPath).
		Int("files", len(files)).Int64("bytes", totalBytes).
		Msg("Encrypt task started")

	go runEncryptTask(task, files, req.Password)

	RespondSuccess(w, map[string]interface{}{
		"taskId":     task.ID,
		"totalFiles": task.TotalFiles,
		"totalBytes": task.TotalBytes,
		"message":    "Encryption started in background",
	})
}

// HandleEncryptTaskStatus returns the status of an encrypt task.
func HandleEncryptTaskStatus(w http.ResponseWriter, r *http.Request) {
	taskID := strings.TrimPrefix(r.URL.Path, "/enc-api/encryptStatus/")
	if taskID == "" {
		RespondAPIError(w, 500, "Missing task ID")
		return
	}

	task := encryptTaskStore.Get(taskID)
	if task == nil {
		RespondAPIError(w, 404, "Task not found")
		return
	}

	snapshot := task.snapshot()
	RespondSuccess(w, map[string]interface{}{
		"taskId":     snapshot.ID,
		"operation":  snapshot.Operation,
		"status":     snapshot.Status,
		"totalFiles": snapshot.TotalFiles,
		"doneFiles":  snapshot.DoneFiles,
		"totalBytes": snapshot.TotalBytes,
		"doneBytes":  snapshot.DoneBytes,
		"percent":    calcPercent(snapshot.DoneBytes, snapshot.TotalBytes),
		"error":      snapshot.Error,
	})
}

// HandleEncryptTaskList returns all encrypt tasks.
func HandleEncryptTaskList(w http.ResponseWriter, r *http.Request) {
	tasks := encryptTaskStore.List()
	snapshots := make([]EncryptTaskView, 0, len(tasks))
	for _, task := range tasks {
		snapshots = append(snapshots, task.snapshot())
	}
	RespondSuccess(w, map[string]interface{}{
		"tasks": snapshots,
	})
}

func calcPercent(done, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(done) / float64(total) * 100
}

func runEncryptTask(task *EncryptTask, files []string, password string) {
	defer func() {
		if r := recover(); r != nil {
			setEncryptTaskError(task, fmt.Sprintf("panic: %v", r))
		}
	}()

	converter := encryption.NewFileNameConverter(password, task.EncType, "")
	srcPath := filepath.Clean(task.SrcPath)
	dstPath := filepath.Clean(task.DstPath)
	tempDir, err := os.MkdirTemp(dstPath, ".encrypt-"+task.ID+"-")
	if err != nil {
		setEncryptTaskError(task, fmt.Sprintf("create temporary directory: %v", err))
		return
	}
	defer os.RemoveAll(tempDir)

	for _, filePath := range files {
		select {
		case <-task.cancel:
			setEncryptTaskError(task, "canceled")
			return
		default:
		}

		relPath := strings.TrimPrefix(filePath, srcPath)
		relPath = strings.TrimPrefix(relPath, string(filepath.Separator))

		// Handle filename encryption/decryption
		if task.EncName {
			dir := filepath.Dir(relPath)
			name := filepath.Base(relPath)
			ext := filepath.Ext(name)
			base := strings.TrimSuffix(name, ext)

			if task.Operation == "enc" {
				newName := converter.EncryptFileName(base) + ext
				relPath = filepath.Join(dir, newName)
			} else {
				decoded := converter.DecryptFileName(base)
				if decoded != "" {
					if !isSafeLocalFileBase(decoded) {
						setEncryptTaskError(task, fmt.Sprintf("unsafe decoded filename %q", decoded))
						return
					}
					relPath = filepath.Join(dir, decoded+ext)
				}
			}
		}

		outFile := filepath.Join(dstPath, relPath)
		outTemp := filepath.Join(tempDir, relPath)

		if err := os.MkdirAll(filepath.Dir(outTemp), 0755); err != nil {
			setEncryptTaskError(task, fmt.Sprintf("mkdir %s: %v", filepath.Dir(outTemp), err))
			return
		}
		if err := os.MkdirAll(filepath.Dir(outFile), 0755); err != nil {
			setEncryptTaskError(task, fmt.Sprintf("mkdir %s: %v", filepath.Dir(outFile), err))
			return
		}

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			setEncryptTaskError(task, fmt.Sprintf("stat %s: %v", filePath, err))
			return
		}
		fileSize := fileInfo.Size()

		if err := processFile(filePath, outTemp, password, task.EncType, fileSize, task.Operation); err != nil {
			setEncryptTaskError(task, fmt.Sprintf("process %s: %v", filePath, err))
			return
		}

		if err := os.Rename(outTemp, outFile); err != nil {
			setEncryptTaskError(task, fmt.Sprintf("publish %s: %v", outFile, err))
			return
		}

		task.mu.Lock()
		task.DoneFiles++
		task.DoneBytes += fileSize
		task.UpdatedAt = time.Now()
		task.mu.Unlock()
	}

	task.mu.Lock()
	task.Status = "done"
	task.UpdatedAt = time.Now()
	doneFiles := task.DoneFiles
	doneBytes := task.DoneBytes
	task.mu.Unlock()

	log.Info().Str("task_id", task.ID).Int("files", doneFiles).
		Int64("bytes", doneBytes).Msg("Encrypt task completed")
}

func isSafeLocalFileBase(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	return !filepath.IsAbs(name) && filepath.VolumeName(name) == "" && filepath.Base(name) == name
}

func setEncryptTaskError(task *EncryptTask, message string) {
	task.mu.Lock()
	task.Status = "error"
	task.Error = message
	task.UpdatedAt = time.Now()
	task.mu.Unlock()
}

func processFile(src, dst, password, encType string, fileSize int64, operation string) (retErr error) {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src: %w", err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create dst: %w", err)
	}
	defer func() {
		if err := out.Close(); retErr == nil && err != nil {
			retErr = fmt.Errorf("close dst: %w", err)
		}
	}()

	if operation == "enc" {
		enc, err := encryption.NewLatestContentEncryptor(password, encType, fileSize)
		if err != nil {
			return fmt.Errorf("create cipher: %w", err)
		}
		reader, err := enc.EncryptReader(in, 0)
		if err != nil {
			return fmt.Errorf("create encrypt reader: %w", err)
		}
		buf := make([]byte, 512*1024)
		_, err = io.CopyBuffer(out, reader, buf)
		return err
	}

	reader, _, err := encryption.AutoDecryptReader(password, encryption.EncType(encType), in, fileSize)
	if err != nil {
		return fmt.Errorf("create decrypt reader: %w", err)
	}
	buf := make([]byte, 512*1024)
	_, err = io.CopyBuffer(out, reader, buf)
	return err
}
