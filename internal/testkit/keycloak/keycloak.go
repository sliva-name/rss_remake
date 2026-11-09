// Package keycloak manages accounts in a Keycloak for the end-to-end tests and
// make demo: the stand's, or the one an installation test brings up.
package keycloak

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
)

const (
	Realm = "dataguard"
	// cliClient allows the password grant; the dashboard client does not.
	cliClient = "dataguard-cli"
)

// Server is one Keycloak.
type Server struct {
	BaseURL string
	HTTP    *http.Client
}

// Stand is the Keycloak of the local stand; its issuer is fixed by the
// Keycloak hostname setting.
var Stand = Server{BaseURL: "http://127.0.0.1:25080", HTTP: http.DefaultClient}

// Admin is a session of the Keycloak administrator in the master realm.
type Admin struct {
	server Server
	token  string
}

// Connect signs in to the stand as the bootstrap administrator.
func Connect(ctx context.Context, password string) (*Admin, error) {
	return Stand.Connect(ctx, password)
}

// Login returns an access token of a user of the stand's platform realm.
func Login(ctx context.Context, username, password string) (string, error) {
	return Stand.Login(ctx, username, password)
}

// Connect signs in as the bootstrap administrator.
func (s Server) Connect(ctx context.Context, password string) (*Admin, error) {
	token, err := s.passwordGrant(ctx, "master", "admin-cli", "dg_admin", password, "")
	if err != nil {
		return nil, fmt.Errorf("keycloak administrator: %w", err)
	}
	return &Admin{server: s, token: token}, nil
}

// Login returns an access token of a user of the platform realm.
func (s Server) Login(ctx context.Context, username, password string) (string, error) {
	return s.passwordGrant(ctx, Realm, cliClient, username, password, "openid")
}

func (s Server) passwordGrant(ctx context.Context, realm, client, username, password, scope string) (string, error) {
	form := url.Values{"grant_type": {"password"}, "client_id": {client}, "username": {username}, "password": {password}}
	if scope != "" {
		form.Set("scope", scope)
	}
	address := s.BaseURL + "/realms/" + realm + "/protocol/openid-connect/token"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := s.HTTP.Do(request)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("sign in as %s: status %d", username, response.StatusCode)
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return "", err
	}
	return decoded.AccessToken, nil
}

// AddPasswordClient adds the client that signs in with a password, which a
// test needs and an installation's realm leaves out: people sign in through the
// dashboard there. Its tokens carry the same claims and audience.
func (a *Admin) AddPasswordClient(ctx context.Context) error {
	mapper := func(name, kind string, config map[string]string) map[string]any {
		return map[string]any{"name": name, "protocol": "openid-connect", "protocolMapper": kind, "config": config}
	}
	response, err := a.do(ctx, http.MethodPost, "/clients", map[string]any{
		"clientId": cliClient, "publicClient": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": true,
		"protocolMappers": []any{
			mapper("tenant_id", "oidc-usermodel-attribute-mapper", map[string]string{
				"user.attribute": "tenant_id", "claim.name": "tenant_id", "jsonType.label": "String", "access.token.claim": "true",
			}),
			mapper("roles", "oidc-usermodel-realm-role-mapper", map[string]string{
				"claim.name": "roles", "multivalued": "true", "jsonType.label": "String", "access.token.claim": "true",
			}),
			mapper("audience", "oidc-audience-mapper", map[string]string{
				"included.client.audience": "dataguard-dashboard", "access.token.claim": "true",
			}),
		},
	})
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusConflict {
		return fmt.Errorf("create the password client: status %d", response.StatusCode)
	}
	return nil
}

// CreateUser replaces any user with that name and returns a new random
// password. tenantID is empty for platform administrators.
func (a *Admin) CreateUser(ctx context.Context, name, role, tenantID string) (string, error) {
	var found []struct{ ID string }
	if err := a.call(ctx, http.MethodGet, "/users?exact=true&username="+url.QueryEscape(name), nil, &found); err != nil {
		return "", err
	}
	for _, user := range found {
		if err := a.call(ctx, http.MethodDelete, "/users/"+user.ID, nil, nil); err != nil {
			return "", err
		}
	}
	secret := make([]byte, 12)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	password := "Dg-" + hex.EncodeToString(secret)
	attributes := map[string][]string{}
	if tenantID != "" {
		attributes["tenant_id"] = []string{tenantID}
	}
	location, err := a.create(ctx, map[string]any{
		"username": name, "enabled": true, "email": name + "@example.invalid", "emailVerified": true,
		"firstName": name, "lastName": "DataGuard", "attributes": attributes,
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}},
	})
	if err != nil {
		return "", err
	}
	var roleBody map[string]any
	if err := a.call(ctx, http.MethodGet, "/roles/"+url.PathEscape(role), nil, &roleBody); err != nil {
		return "", err
	}
	if err := a.call(ctx, http.MethodPost, "/users/"+path.Base(location)+"/role-mappings/realm", []any{roleBody}, nil); err != nil {
		return "", err
	}
	return password, nil
}

func (a *Admin) create(ctx context.Context, user map[string]any) (string, error) {
	response, err := a.do(ctx, http.MethodPost, "/users", user)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create user: status %d", response.StatusCode)
	}
	return response.Header.Get("Location"), nil
}

func (a *Admin) call(ctx context.Context, method, route string, body, into any) error {
	response, err := a.do(ctx, method, route, body)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%s %s: status %d", method, route, response.StatusCode)
	}
	if into == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	return json.NewDecoder(response.Body).Decode(into)
}

func (a *Admin) do(ctx context.Context, method, route string, body any) (*http.Response, error) {
	var reader io.Reader = http.NoBody
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, a.server.BaseURL+"/admin/realms/"+Realm+route, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+a.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := a.server.HTTP.Do(request)
	if err != nil {
		return nil, errors.Join(errors.New("keycloak is not reachable"), err)
	}
	return response, nil
}
