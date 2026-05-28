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
	Password   string    `json:"-"`
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
	mu         sync.Mutex
	cancel     chan struct{}
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
	filepath.WalkDir(req.SrcPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 {
			return nil
		}
		files = append(files, path)
		totalBytes += info.Size()
		return nil
	})

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
		Password:   req.Password,
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

	go runEncryptTask(task, files)

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

	RespondSuccess(w, map[string]interface{}{
		"taskId":     task.ID,
		"operation":  task.Operation,
		"status":     task.Status,
		"totalFiles": task.TotalFiles,
		"doneFiles":  task.DoneFiles,
		"totalBytes": task.TotalBytes,
		"doneBytes":  task.DoneBytes,
		"percent":    calcPercent(task.DoneBytes, task.TotalBytes),
		"error":      task.Error,
	})
}

// HandleEncryptTaskList returns all encrypt tasks.
func HandleEncryptTaskList(w http.ResponseWriter, r *http.Request) {
	tasks := encryptTaskStore.List()
	RespondSuccess(w, map[string]interface{}{
		"tasks": tasks,
	})
}

func calcPercent(done, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(done) / float64(total) * 100
}

func runEncryptTask(task *EncryptTask, files []string) {
	defer func() {
		if r := recover(); r != nil {
			task.mu.Lock()
			task.Status = "error"
			task.Error = fmt.Sprintf("panic: %v", r)
			task.UpdatedAt = time.Now()
			task.mu.Unlock()
		}
	}()

	converter := encryption.NewFileNameConverter(task.Password, task.EncType, "")
	srcPath := filepath.Clean(task.SrcPath)
	dstPath := filepath.Clean(task.DstPath)
	tempDir := filepath.Join(dstPath, ".temp")
	os.MkdirAll(tempDir, 0755)

	for _, filePath := range files {
		select {
		case <-task.cancel:
			task.mu.Lock()
			task.Status = "error"
			task.Error = "canceled"
			task.UpdatedAt = time.Now()
			task.mu.Unlock()
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
					relPath = filepath.Join(dir, decoded+ext)
				}
			}
		}

		outFile := filepath.Join(dstPath, relPath)
		outTemp := filepath.Join(tempDir, relPath)

		if err := os.MkdirAll(filepath.Dir(outTemp), 0755); err != nil {
			task.mu.Lock()
			task.Status = "error"
			task.Error = fmt.Sprintf("mkdir %s: %v", filepath.Dir(outTemp), err)
			task.UpdatedAt = time.Now()
			task.mu.Unlock()
			return
		}

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			continue
		}
		fileSize := fileInfo.Size()

		if err := processFile(filePath, outTemp, task.Password, task.EncType, fileSize, task.Operation); err != nil {
			task.mu.Lock()
			task.Status = "error"
			task.Error = fmt.Sprintf("process %s: %v", filePath, err)
			task.UpdatedAt = time.Now()
			task.mu.Unlock()
			return
		}

		os.Rename(outTemp, outFile)

		task.mu.Lock()
		task.DoneFiles++
		task.DoneBytes += fileSize
		task.UpdatedAt = time.Now()
		task.mu.Unlock()
	}

	os.RemoveAll(tempDir)

	task.mu.Lock()
	task.Status = "done"
	task.UpdatedAt = time.Now()
	task.mu.Unlock()

	log.Info().Str("task_id", task.ID).Int("files", task.DoneFiles).
		Int64("bytes", task.DoneBytes).Msg("Encrypt task completed")
}

func processFile(src, dst, password, encType string, fileSize int64, operation string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src: %w", err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create dst: %w", err)
	}
	defer out.Close()

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
