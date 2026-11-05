package handler

import (
	"context"

	"github.com/alist-encrypt-go/internal/quota"
)

// wopanQuotaProvider adapts the WoPan client to the quota registry. It reuses
// wopanPersonal so this endpoint and the rest of the WoPan admin surface cannot
// disagree about which account a storage means.
type wopanQuotaProvider struct {
	admin *WopanAdminHandler
}

func newWopanQuotaProvider(admin *WopanAdminHandler) quota.Provider {
	if admin == nil || admin.provider == nil {
		return nil
	}
	return &wopanQuotaProvider{admin: admin}
}

func (p *wopanQuotaProvider) Supports(driver string) bool { return driver == "WoPan" }

func (p *wopanQuotaProvider) Quota(ctx context.Context, s quota.Storage) (quota.Result, error) {
	if p == nil || p.admin == nil || p.admin.provider == nil || s.Addition == nil {
		return quota.Result{}, quota.Invalid()
	}
	raw, err := s.Addition(ctx)
	if err != nil {
		return quota.Result{}, err
	}
	addition, err := wopanPersonal(wopanStorage{ID: s.ID, MountPath: s.MountPath, Driver: s.Driver, Disabled: s.Disabled, Status: s.Status, Addition: raw})
	if err != nil {
		return quota.Result{}, err
	}
	account, err := p.admin.provider.Account(ctx, addition.AccessToken)
	if err != nil {
		return quota.Result{}, err
	}
	if account.ID == "" {
		return quota.Result{}, quota.Invalid()
	}
	value, err := p.admin.provider.Quota(ctx, addition.AccessToken, account.ID)
	if err != nil {
		return quota.Result{}, err
	}
	// The WoPan client reports an availability that must reconcile exactly with
	// total and used. A mismatch is a provider bug, never a partial answer, so
	// it must not reach the caller as a smaller but plausible number.
	if value.TotalBytes <= 0 || value.UsedBytes < 0 || value.UsedBytes > value.TotalBytes || value.AvailableBytes < 0 || value.AvailableBytes != value.TotalBytes-value.UsedBytes {
		return quota.Result{}, quota.Invalid()
	}
	result := quota.Result{Scope: "personal", Total: value.TotalBytes, Used: value.UsedBytes}
	if err := result.Validate(); err != nil {
		return quota.Result{}, err
	}
	return result, nil
}
