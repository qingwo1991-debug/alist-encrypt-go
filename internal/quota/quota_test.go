package quota

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type fakeProvider struct {
	driver string
	result Result
	err    error
}

func (f *fakeProvider) Supports(driver string) bool { return driver == f.driver }

func (f *fakeProvider) Quota(context.Context, Storage) (Result, error) {
	return f.result, f.err
}

// The registry must dispatch purely by driver name so the request path never
// learns which providers exist and providers never learn about each other.
func TestRegistryDispatchesByDriver(t *testing.T) {
	wopan := &fakeProvider{driver: "WoPan", result: Result{Scope: "personal", Total: 100, Used: 10}}
	yun139 := &fakeProvider{driver: "139Yun", result: Result{Scope: "personal", Total: 200, Used: 20}}
	registry := NewRegistry(wopan, nil, yun139)

	for driver, want := range map[string]Provider{"WoPan": wopan, "139Yun": yun139} {
		got, ok := registry.Provider(driver)
		if !ok || got != want {
			t.Fatalf("%s resolved to %v (ok=%v)", driver, got, ok)
		}
		if !registry.Supports(driver) {
			t.Fatalf("%s not supported", driver)
		}
	}
	for _, driver := range []string{"Local", "GoogleDrive", "189CloudPC", ""} {
		if _, ok := registry.Provider(driver); ok {
			t.Fatalf("%s resolved to a provider", driver)
		}
		if registry.Supports(driver) {
			t.Fatalf("%s reported supported", driver)
		}
	}
}

func TestRegistryToleratesNil(t *testing.T) {
	var registry *Registry
	if _, ok := registry.Provider("WoPan"); ok {
		t.Fatal("nil registry resolved a provider")
	}
	if NewRegistry(nil, nil).Supports("WoPan") {
		t.Fatal("registry of nils reported support")
	}
}

// A provider answer that cannot describe a real account must be rejected rather
// than rendered as a plausible number.
func TestResultValidateRejectsImpossibleAnswers(t *testing.T) {
	for name, result := range map[string]Result{
		"zero total":       {Total: 0, Used: 0},
		"negative total":   {Total: -1, Used: 0},
		"negative used":    {Total: 100, Used: -1},
		"over quota flag":  {Total: 100, Used: 10, OverQuota: true},
		"missing overflag": {Total: 100, Used: 200, OverQuota: false},
	} {
		if err := result.Validate(); err == nil {
			t.Fatalf("%s accepted: %+v", name, result)
		}
	}
	for name, result := range map[string]Result{
		"empty account": {Total: 100, Used: 0},
		"partial":       {Total: 100, Used: 40},
		"over quota":    {Total: 100, Used: 140, OverQuota: true},
	} {
		if err := result.Validate(); err != nil {
			t.Fatalf("%s rejected: %v", name, err)
		}
	}
}

func TestErrorCarriesStatusAndCode(t *testing.T) {
	var failure *Error
	if !errors.As(Invalid(), &failure) || failure.Status != http.StatusBadGateway || failure.Code != "provider_invalid_response" {
		t.Fatalf("invalid error=%v", Invalid())
	}
	if !errors.As(Rejected(), &failure) || failure.Code != "provider_rejected" {
		t.Fatalf("rejected error=%v", Rejected())
	}
}
