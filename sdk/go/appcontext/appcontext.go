// Package appcontext links a database transaction to the application user behind
// it. The application signs a short-lived token and sets it in the transaction;
// the DataGuard agent verifies the signature when it reads the audit log. A
// technical account therefore cannot name a user without the signing key.
//
// The token states what the application claims. It proves the application said
// so, not that a person was present.
package appcontext

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	tokenVersion = "v1"
	parts        = 3
	// DefaultTTL keeps a leaked token useless soon after a transaction ends.
	DefaultTTL = time.Minute
)

// ErrInvalid means the token must not be trusted. No details are given on purpose.
var ErrInvalid = errors.New("application context is invalid")

var subjectPattern = regexp.MustCompile(`^[0-9A-Za-z_.:@-]{1,128}$`)

// Claims is what an application attests.
type Claims struct {
	Subject     string `json:"sub"`
	Application string `json:"app"`
	Trace       string `json:"trc,omitempty"`
	// DatabaseUser binds the token to one login, so it cannot be replayed through
	// another account.
	DatabaseUser string `json:"dbu,omitempty"`
	ExpiresAt    int64  `json:"exp"`
}

// Signer issues tokens for one application.
type Signer struct {
	application string
	key         ed25519.PrivateKey
	ttl         time.Duration
	now         func() time.Time
}

// NewSigner creates a signer. Keep the private key in the application's secret
// store; the agent only needs the public part.
func NewSigner(application string, key ed25519.PrivateKey) *Signer {
	return &Signer{application: application, key: key, ttl: DefaultTTL, now: time.Now}
}

// Token signs a context for subject.
func (s *Signer) Token(subject, databaseUser, trace string) (string, error) {
	if !subjectPattern.MatchString(subject) {
		return "", errors.New("subject must be a stable identifier, not a display name")
	}
	payload, err := json.Marshal(Claims{
		Subject: subject, Application: s.application, Trace: trace, DatabaseUser: databaseUser,
		ExpiresAt: s.now().Add(s.ttl).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("encode context: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	message := tokenVersion + "." + encoded
	return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.key, []byte(message))), nil
}

// Statement returns the SQL that sets a token. SET LOCAL ties it to the current
// transaction, so it cannot leak to the next user of a pooled connection. It is a
// literal rather than a parameter because pgAudit logs the statement text, which
// is how the agent sees it; the token alphabet cannot break out of the quotes.
func Statement(token string) string {
	return "SET LOCAL dg.ctx = '" + token + "'"
}

// Execer is satisfied by *sql.Tx.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Apply sets the token in tx. Call it first in every transaction.
func Apply(ctx context.Context, tx Execer, token string) error {
	if _, err := tx.ExecContext(ctx, Statement(token)); err != nil {
		return fmt.Errorf("set application context: %w", err)
	}
	return nil
}

// Verify checks a token against the application's public keys at the given time.
func Verify(token string, keys map[string]ed25519.PublicKey, databaseUser string, at time.Time) (Claims, error) {
	segments := strings.Split(token, ".")
	if len(segments) != parts || segments[0] != tokenVersion {
		return Claims{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return Claims{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, ErrInvalid
	}
	key, known := keys[claims.Application]
	if !known || !ed25519.Verify(key, []byte(tokenVersion+"."+segments[1]), signature) {
		return Claims{}, ErrInvalid
	}
	if !at.Before(time.Unix(claims.ExpiresAt, 0)) || !subjectPattern.MatchString(claims.Subject) {
		return Claims{}, ErrInvalid
	}
	if claims.DatabaseUser != "" && claims.DatabaseUser != databaseUser {
		return Claims{}, ErrInvalid
	}
	return claims, nil
}
