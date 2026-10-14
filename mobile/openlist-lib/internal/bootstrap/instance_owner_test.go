package bootstrap

import (
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	internalnet "github.com/OpenListTeam/OpenList/v4/internal/net"
	"testing"
	"time"
)

func TestBootstrapLegacyEntrypointsRejectEmbeddedOwnerBeforeSideEffects(t *testing.T) {
	owner, err := internalnet.AcquireEmbeddedLease()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.BeginStop(); _ = owner.Release() }()
	configBefore, dbBefore := conf.Conf, db.GetDb()
	if err := Init(); err == nil {
		t.Fatal("unowned Init accepted")
	}
	if err := Start(); err == nil {
		t.Fatal("unowned Start accepted")
	}
	if err := Release(); err == nil {
		t.Fatal("unowned Release accepted")
	}
	if err := ShutdownOwned(nil, time.Second); err == nil {
		t.Fatal("unowned Shutdown accepted")
	}
	if conf.Conf != configBefore || db.GetDb() != dbBefore {
		t.Fatal("rejected entrypoint changed config/DB")
	}
	endpointOwnerMu.Lock()
	remaining := endpointOwner
	endpointOwnerMu.Unlock()
	if remaining != nil {
		t.Fatal("unowned Start created endpoint generation")
	}
	if err := internalnet.AuthorizeBootstrap(owner); err != nil {
		t.Fatal(err)
	}
}
