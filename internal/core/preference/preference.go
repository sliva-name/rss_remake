// Package preference keeps personal settings of an account: saved views,
// favourites, recently opened objects and the overview layout. The center
// stores them as given; they are references and filters, never data values.
package preference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Keys are the kinds of settings an account can keep.
const (
	Views     = "views"
	Favorites = "favorites"
	Recent    = "recent"
	Overview  = "overview"
)

// MaxBytes bounds one setting. Views and favourites of a heavy user fit many
// times over; a client storing more than this is doing something else.
const MaxBytes = 64 << 10

// ErrInvalid marks a setting the center refuses to keep.
var ErrInvalid = errors.New("invalid preference")

// Owner is the account whose settings these are, inside one organization.
type Owner struct {
	TenantID uuid.UUID
	Subject  string
}

type Store interface {
	// GetPreference returns nil when the setting was never saved.
	GetPreference(ctx context.Context, owner Owner, key string) (json.RawMessage, error)
	PutPreference(ctx context.Context, owner Owner, key string, value json.RawMessage) error
}

type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func known(key string) bool {
	return key == Views || key == Favorites || key == Recent || key == Overview
}

func (s *Service) Get(ctx context.Context, owner Owner, key string) (json.RawMessage, error) {
	if !known(key) {
		return nil, fmt.Errorf("%w: unknown key", ErrInvalid)
	}
	return s.store.GetPreference(ctx, owner, key)
}

func (s *Service) Put(ctx context.Context, owner Owner, key string, value json.RawMessage) error {
	switch {
	case !known(key):
		return fmt.Errorf("%w: unknown key", ErrInvalid)
	case len(value) > MaxBytes:
		return fmt.Errorf("%w: larger than %d bytes", ErrInvalid, MaxBytes)
	case !json.Valid(value):
		return fmt.Errorf("%w: not JSON", ErrInvalid)
	}
	return s.store.PutPreference(ctx, owner, key, value)
}
