package op_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/glebarez/sqlite"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func init() {
	dB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	conf.Conf = conf.DefaultConfig("data")
	db.Init(dB)
}

func TestCreateStorage(t *testing.T) {
	var storages = []struct {
		storage model.Storage
		isErr   bool
	}{
		{storage: model.Storage{Driver: "Local", MountPath: "/local", Addition: `{"root_folder_path":"."}`}, isErr: false},
		{storage: model.Storage{Driver: "Local", MountPath: "/local", Addition: `{"root_folder_path":"."}`}, isErr: true},
		{storage: model.Storage{Driver: "None", MountPath: "/none", Addition: `{"root_folder_path":"."}`}, isErr: true},
	}
	for _, storage := range storages {
		_, err := op.CreateStorage(context.Background(), storage.storage)
		if err != nil {
			if !storage.isErr {
				t.Errorf("failed to create storage: %+v", err)
			} else {
				t.Logf("expect failed to create storage: %+v", err)
			}
		}
	}
}

func TestCreateStorageInvalidAdditionLogDoesNotLeakCredentials(t *testing.T) {
	logger := log.StandardLogger()
	previousOutput := logger.Out
	previousFormatter := logger.Formatter
	previousLevel := logger.Level
	t.Cleanup(func() {
		logger.SetOutput(previousOutput)
		logger.SetFormatter(previousFormatter)
		logger.SetLevel(previousLevel)
	})

	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(&log.TextFormatter{DisableColors: true, DisableTimestamp: true})
	logger.SetLevel(log.DebugLevel)

	const secret = "credential-sentinel-do-not-log"
	addition := `{"root_folder_path":".","password":"` + secret + `"`
	mountPath := fmt.Sprintf("/invalid-addition-log-redaction-%d", time.Now().UnixNano())
	_, err := op.CreateStorage(context.Background(), model.Storage{
		Driver:    "Local",
		MountPath: mountPath,
		Addition:  addition,
	})
	if err == nil {
		t.Fatal("expected invalid addition JSON to fail")
	}

	logged := output.String()
	if !strings.Contains(logged, "[storage_init] addition unmarshal failed") {
		t.Fatalf("expected a safe addition parse warning, got %q", logged)
	}
	for _, sensitive := range []string{secret, addition, `"password"`} {
		if strings.Contains(logged, sensitive) {
			t.Fatalf("log leaked sensitive addition data %q: %s", sensitive, logged)
		}
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("returned error leaked sensitive addition data %q: %v", sensitive, err)
		}
	}
}

func TestGetStorageVirtualFilesByPath(t *testing.T) {
	setupStorages(t)
	virtualFiles := op.GetStorageVirtualFilesByPath("/a")
	var names []string
	for _, virtualFile := range virtualFiles {
		names = append(names, virtualFile.GetName())
	}
	var expectedNames = []string{"b", "c", "d"}
	if utils.SliceEqual(names, expectedNames) {
		t.Logf("passed")
	} else {
		t.Errorf("expected: %+v, got: %+v", expectedNames, names)
	}
}

func TestGetBalancedStorage(t *testing.T) {
	set := mapset.NewSet[string]()
	for i := 0; i < 5; i++ {
		storage := op.GetBalancedStorage("/a/d/e1")
		set.Add(storage.GetStorage().MountPath)
	}
	expected := mapset.NewSet([]string{"/a/d/e1", "/a/d/e1.balance"}...)
	if !expected.Equal(set) {
		t.Errorf("expected: %+v, got: %+v", expected, set)
	}
}

func setupStorages(t *testing.T) {
	var storages = []model.Storage{
		{Driver: "Local", MountPath: "/a/b", Order: 0, Addition: `{"root_folder_path":"."}`},
		{Driver: "Local", MountPath: "/adc", Order: 0, Addition: `{"root_folder_path":"."}`},
		{Driver: "Local", MountPath: "/a/c", Order: 1, Addition: `{"root_folder_path":"."}`},
		{Driver: "Local", MountPath: "/a/d", Order: 2, Addition: `{"root_folder_path":"."}`},
		{Driver: "Local", MountPath: "/a/d/e1", Order: 3, Addition: `{"root_folder_path":"."}`},
		{Driver: "Local", MountPath: "/a/d/e", Order: 4, Addition: `{"root_folder_path":"."}`},
		{Driver: "Local", MountPath: "/a/d/e1.balance", Order: 4, Addition: `{"root_folder_path":"."}`},
	}
	for _, storage := range storages {
		_, err := op.CreateStorage(context.Background(), storage)
		if err != nil {
			t.Fatalf("failed to create storage: %+v", err)
		}
	}
}
