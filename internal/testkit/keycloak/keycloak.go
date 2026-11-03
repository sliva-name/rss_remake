// Package keycloak manages accounts in the stand's Keycloak for the end-to-end
// test and for make dev-users.
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

// Stand addresses: the issuer is fixed by the Keycloak hostname setting.
const (
	BaseURL = "http://127.0.0.1:25080"
	Realm   = "dataguard"
	// cliClient allows the password grant; the dashboard client does not.
	cliClient = "dataguard-cli"
)

// Admin is a session of the Keycloak administrator in the master realm.
type Admin struct {
	token string
}

// Connect signs in as the bootstrap administrator.
func Connect(ctx context.Context, password string) (*Admin, error) {
	token, err := passwordGrant(ctx, "master", "admin-cli", "dg_admin", password, "")
	if err != nil {
		return nil, fmt.Errorf("keycloak administrator: %w", err)
	}
	return &Admin{token: token}, nil
}

// Login returns an access token of a user of the platform realm.
func Login(ctx context.Context, username, password string) (string, error) {
	return passwordGrant(ctx, Realm, cliClient, username, password, "openid")
}

func passwordGrant(ctx context.Context, realm, client, username, password, scope string) (string, error) {
	form := url.Values{"grant_type": {"password"}, "client_id": {client}, "username": {username}, "password": {password}}
	if scope != "" {
		form.Set("scope", scope)
	}
	address := BaseURL + "/realms/" + realm + "/protocol/openid-connect/token"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
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
	request, err := http.NewRequestWithContext(ctx, method, BaseURL+"/admin/realms/"+Realm+route, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+a.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, errors.Join(errors.New("keycloak is not reachable, run make dev-up"), err)
	}
	return response, nil
}
