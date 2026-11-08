package api

import (
	"reflect"
	"slices"
	"testing"

	"github.com/google/uuid"

	"dataguard/internal/gen/restapi"
)

func TestEveryOperationHasAnAccessRuleAndAPermission(t *testing.T) {
	operations := reflect.TypeFor[restapi.StrictServerInterface]()
	names := make([]string, 0, operations.NumMethod())
	for method := range operations.Methods() {
		name := method.Name
		names = append(names, name)
		if _, ok := accessRules[name]; !ok {
			t.Errorf("operation %s has no access rule", name)
		}
		if !restapi.Permission(contractName(name)).Valid() {
			t.Errorf("operation %s is missing from the Permission enum", name)
		}
	}
	for name := range accessRules {
		if !slices.Contains(names, name) {
			t.Errorf("access rule %s matches no operation", name)
		}
	}
}

var samplePrincipals = map[string]Principal{
	"no roles":                     {Subject: "nobody", TenantID: uuid.New()},
	"platform admin":               {Subject: "platform", Roles: []string{RolePlatformAdmin}},
	"tenant admin":                 {Subject: "admin", TenantID: uuid.New(), Roles: []string{RoleTenantAdmin}},
	"analyst and auditor":          {Subject: "both", TenantID: uuid.New(), Roles: []string{RoleSecurityAnalyst, RoleAuditor}},
	"auditor":                      {Subject: "auditor", TenantID: uuid.New(), Roles: []string{RoleAuditor}},
	"tenant role without a tenant": {Subject: "lost", Roles: []string{RoleTenantAdmin}},
	"platform and tenant admin":    {Subject: "both-levels", TenantID: uuid.New(), Roles: []string{RolePlatformAdmin, RoleTenantAdmin}},
}

func TestPermissionsAreExactlyWhatTheAPIAllows(t *testing.T) {
	for label, principal := range samplePrincipals {
		permissions := permissionsOf(principal)
		ctx := withPrincipal(t.Context(), principal)
		for operationID := range accessRules {
			allowed := checkAccess(ctx, operationID) == nil
			listed := slices.Contains(permissions, restapi.Permission(contractName(operationID)))
			if allowed != listed {
				t.Errorf("%s, %s: API allows %v, permissions list %v", label, operationID, allowed, listed)
			}
		}
	}
}

func TestPermissionsOfSeveralRolesAreTheirUnion(t *testing.T) {
	both := permissionsOf(samplePrincipals["analyst and auditor"])
	auditor := permissionsOf(samplePrincipals["auditor"])
	for _, permission := range auditor {
		if !slices.Contains(both, permission) {
			t.Errorf("auditor may %s, analyst and auditor may not", permission)
		}
	}
	if !slices.Contains(both, restapi.RequestScan) || slices.Contains(auditor, restapi.RequestScan) {
		t.Error("requesting a scan should come from the analyst role only")
	}

	levels := permissionsOf(samplePrincipals["platform and tenant admin"])
	for _, permission := range []restapi.Permission{restapi.CreateTenant, restapi.CreateSource} {
		if !slices.Contains(levels, permission) {
			t.Errorf("platform and tenant admin should have %s", permission)
		}
	}
}

func TestPlatformAdminWithoutTenantGetsOnlyOrganizations(t *testing.T) {
	got := permissionsOf(samplePrincipals["platform admin"])
	want := []restapi.Permission{restapi.CreateTenant, restapi.GetCurrentUser, restapi.ListTenants}
	if !slices.Equal(got, want) {
		t.Errorf("permissions = %v, want %v", got, want)
	}
}
