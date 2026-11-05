// Package quota resolves the quota of a mounted storage from the provider that
// backs it. A caller asks the registry for a driver and receives either exact
// bytes or an explicit "no provider"; nothing here guesses, and an absent value
// is never rendered as a zero.
package quota

import (
	"context"
	"net/http"
)

// Storage is the part of an OpenList storage record a provider may inspect.
//
// Addition is a loader rather than a value: the raw record costs an upstream
// round trip, and list responses hide additions on purpose, so only the
// provider that actually owns the driver pays for it.
type Storage struct {
	ID        int
	MountPath string
	Driver    string
	// Disabled and Status mirror the storage record. A provider must not query
	// a mount the upstream has disabled or not brought up.
	Disabled bool
	Status   string
	Addition func(ctx context.Context) (string, error)
}

// Result is a provider-neutral quota answer.
//
// OverQuota records that the account reports more used than total. Such an
// account has no available bytes to report, so the caller omits the field
// instead of publishing a negative count.
type Result struct {
	Scope     string
	Total     int64
	Used      int64
	OverQuota bool
}

// Error carries the HTTP status and stable code a provider wants surfaced.
// Providers never write responses; the transport layer owns that mapping.
type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string { return e.Code }

// Invalid reports an answer that cannot describe a real account.
func Invalid() error {
	return &Error{Status: http.StatusBadGateway, Code: "provider_invalid_response"}
}

// Rejected reports that the provider refused the credential or the request.
func Rejected() error {
	return &Error{Status: http.StatusBadGateway, Code: "provider_rejected"}
}

// Validate rejects a result that cannot be a real quota. It is applied by the
// caller as well as by providers so no implementation can publish a negative
// used count or an availability flag that contradicts the byte counts.
func (r Result) Validate() error {
	if r.Total <= 0 || r.Used < 0 || r.OverQuota != (r.Used > r.Total) {
		return Invalid()
	}
	return nil
}

// Provider answers quota for one family of drivers.
type Provider interface {
	// Supports reports whether this provider owns driver.
	Supports(driver string) bool
	// Quota resolves one storage. It must return Invalid rather than a zero
	// result when the provider answered something impossible.
	Quota(ctx context.Context, s Storage) (Result, error)
}

// Registry dispatches by driver name. Resolution follows registration order, so
// the first provider that claims a driver wins and providers stay unaware of
// each other.
type Registry struct {
	providers []Provider
}

// NewRegistry builds a registry, dropping nil providers so an optional client
// cannot turn every lookup into a panic.
func NewRegistry(providers ...Provider) *Registry {
	filtered := make([]Provider, 0, len(providers))
	for _, p := range providers {
		if p != nil {
			filtered = append(filtered, p)
		}
	}
	return &Registry{providers: filtered}
}

// Provider returns the provider that owns driver.
func (r *Registry) Provider(driver string) (Provider, bool) {
	if r == nil {
		return nil, false
	}
	for _, p := range r.providers {
		if p.Supports(driver) {
			return p, true
		}
	}
	return nil, false
}

// Supports reports whether any provider owns driver.
func (r *Registry) Supports(driver string) bool {
	_, ok := r.Provider(driver)
	return ok
}
