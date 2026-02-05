package restart

import "sync"

var (
	restartChan chan struct{}
	mu          sync.Mutex
)

// SetChan sets the restart channel
func SetChan(ch chan struct{}) {
	mu.Lock()
	defer mu.Unlock()
	restartChan = ch
}

// Trigger signals the server to restart
func Trigger() {
	mu.Lock()
	defer mu.Unlock()
	if restartChan != nil {
		close(restartChan)
		restartChan = nil
	}
}
