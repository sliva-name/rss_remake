package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"

	"dataguard/internal/core/oplog"
)

// Roles carried in the identity token.
const (
	RolePlatformAdmin   = "platform_admin"
	RoleTenantAdmin     = "tenant_admin"
	RoleSecurityAnalyst = "security_analyst"
	RoleAuditor         = "auditor"
)

var (
	errUnauthenticated = errors.New("authentication required")
	errForbidden       = errors.New("not allowed")
	errNoTenant        = errors.New("account is not assigned to a tenant")
)

// Principal is the authenticated caller. TenantID is uuid.Nil for platform
// administrators, who manage organizations but see no tenant data.
type Principal struct {
	Subject string
	// Name is the login the provider shows people; it may be empty.
	Name     string
	TenantID uuid.UUID
	Roles    []string
}

func (p Principal) displayName() string {
	if p.Name != "" {
		return p.Name
	}
	return p.Subject
}

func (p Principal) hasAnyRole(roles []string) bool {
	return slices.ContainsFunc(roles, func(role string) bool { return slices.Contains(p.Roles, role) })
}

// Authenticator turns a bearer token into a Principal.
type Authenticator interface {
	Authenticate(ctx context.Context, bearerToken string) (Principal, error)
}

// OIDCAuthenticator validates tokens against any OIDC provider.
type OIDCAuthenticator struct {
	verifier *oidc.IDTokenVerifier
}

// NewOIDCAuthenticator discovers the provider at issuer. A non-empty discoveryURL
// is where the server reaches the same provider when the browser and the server
// see it under different addresses, as in containers. Tokens must still carry
// issuer, and the provider must announce it. client reaches the provider, for
// discovery and its signing keys later; nil is the default client.
func NewOIDCAuthenticator(ctx context.Context, issuer, discoveryURL, clientID string, client *http.Client) (*OIDCAuthenticator, error) {
	if client != nil {
		ctx = oidc.ClientContext(ctx, client)
	}
	if discoveryURL == "" {
		discoveryURL = issuer
	} else {
		ctx = oidc.InsecureIssuerURLContext(ctx, issuer)
	}
	provider, err := oidc.NewProvider(ctx, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("discover oidc provider: %w", err)
	}
	return &OIDCAuthenticator{verifier: provider.Verifier(&oidc.Config{ClientID: clientID})}, nil
}

func (a *OIDCAuthenticator) Authenticate(ctx context.Context, bearerToken string) (Principal, error) {
	token, err := a.verifier.Verify(ctx, bearerToken)
	if err != nil {
		return Principal{}, errUnauthenticated
	}
	var claims struct {
		TenantID string   `json:"tenant_id"`
		Roles    []string `json:"roles"`
		Username string   `json:"preferred_username"`
	}
	if err := token.Claims(&claims); err != nil {
		return Principal{}, errUnauthenticated
	}
	principal := Principal{Subject: token.Subject, Name: claims.Username, Roles: claims.Roles}
	if claims.TenantID == "" {
		return principal, nil
	}
	if principal.TenantID, err = uuid.Parse(claims.TenantID); err != nil {
		return Principal{}, errUnauthenticated
	}
	return principal, nil
}

type principalKey struct{}

func withPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

func principalFrom(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalKey{}).(Principal)
	return principal, ok
}

func authenticate(authenticator Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !found || token == "" {
			writeProblem(w, http.StatusUnauthorized, "unauthenticated", errUnauthenticated.Error())
			return
		}
		principal, err := authenticator.Authenticate(r.Context(), token)
		if err != nil {
			writeProblem(w, http.StatusUnauthorized, "unauthenticated", errUnauthenticated.Error())
			return
		}
		// Every change made through this request is journaled as the principal's.
		ctx := oplog.WithActor(withPrincipal(r.Context(), principal), oplog.Actor{Subject: principal.Subject, Name: principal.displayName()})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
