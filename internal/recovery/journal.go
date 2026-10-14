package recovery

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// WriteMarker is an exclusive-offline operation. No running service calls it.
// A directory-sync error after rename leaves the restrictive marker in place.
func WriteMarker(dir string, m Marker) (err error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".recovery-state-")
	if err != nil {
		return err
	}
	p := f.Name()
	defer os.Remove(p)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(p, filepath.Join(dir, SidecarName)); err != nil {
		return err
	}
	return SyncDir(dir)
}
func SyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
