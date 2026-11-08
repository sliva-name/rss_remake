package api

import (
	"context"
	"net/http"
	"slices"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"dataguard/internal/gen/restapi"
)

var (
	tenantReaders  = []string{RoleTenantAdmin, RoleSecurityAnalyst, RoleAuditor}
	tenantAdmins   = []string{RoleTenantAdmin}
	scanRequesters = []string{RoleTenantAdmin, RoleSecurityAnalyst}
	platformOnly   = []string{RolePlatformAdmin}
	anyRole        = []string{RolePlatformAdmin, RoleTenantAdmin, RoleSecurityAnalyst, RoleAuditor}
)

// accessRule says who may call an operation. tenantScoped operations also
// require the caller to belong to a tenant.
type accessRule struct {
	roles        []string
	tenantScoped bool
}

// accessRules is deny-by-default: an operation missing here is refused, so a
// new endpoint cannot ship open by accident.
var accessRules = map[string]accessRule{
	"GetCurrentUser":        {roles: anyRole},
	"ListTenants":           {roles: platformOnly},
	"CreateTenant":          {roles: platformOnly},
	"ListEnvironments":      {roles: tenantReaders, tenantScoped: true},
	"CreateEnvironment":     {roles: tenantAdmins, tenantScoped: true},
	"CreateEnrollmentToken": {roles: tenantAdmins, tenantScoped: true},
	"ListAgents":            {roles: tenantReaders, tenantScoped: true},
	"GetAgent":              {roles: tenantReaders, tenantScoped: true},
	"RevokeAgent":           {roles: tenantAdmins, tenantScoped: true},
	"ListSources":           {roles: tenantReaders, tenantScoped: true},
	"GetSource":             {roles: tenantReaders, tenantScoped: true},
	"CreateSource":          {roles: tenantAdmins, tenantScoped: true},
	"UpdateSource":          {roles: tenantAdmins, tenantScoped: true},
	"DeleteSource":          {roles: tenantAdmins, tenantScoped: true},
	"ListScans":             {roles: tenantReaders, tenantScoped: true},
	"RequestScan":           {roles: scanRequesters, tenantScoped: true},
	"ListCatalogColumns":    {roles: tenantReaders, tenantScoped: true},
	"GetCatalogColumn":      {roles: tenantReaders, tenantScoped: true},
	"ListCatalogTables":     {roles: tenantReaders, tenantScoped: true},
	"GetCatalogTable":       {roles: tenantReaders, tenantScoped: true},
	"GetCatalogSummary":     {roles: tenantReaders, tenantScoped: true},
	"ListCatalogChanges":    {roles: tenantReaders, tenantScoped: true},
	"ListAuditEvents":       {roles: tenantReaders, tenantScoped: true},
	"GetAuditCoverage":      {roles: tenantReaders, tenantScoped: true},
	"GetAccessSummary":      {roles: tenantReaders, tenantScoped: true},
	"ListAccessByPrincipal": {roles: tenantReaders, tenantScoped: true},
	"ListAccessByCategory":  {roles: tenantReaders, tenantScoped: true},
	"GetPolicy":             {roles: tenantReaders, tenantScoped: true},
	"PublishPolicy":         {roles: tenantAdmins, tenantScoped: true},
}

func authorize(next restapi.StrictHandlerFunc, operationID string) restapi.StrictHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		if err := checkAccess(ctx, operationID); err != nil {
			return nil, err
		}
		return next(ctx, w, r, request)
	}
}

func checkAccess(ctx context.Context, operationID string) error {
	rule, known := accessRules[operationID]
	principal, authenticated := principalFrom(ctx)
	switch {
	case !authenticated:
		return errUnauthenticated
	case !known || !principal.hasAnyRole(rule.roles):
		return errForbidden
	case rule.tenantScoped && principal.TenantID == uuid.Nil:
		return errNoTenant
	default:
		return nil
	}
}

// permissionsOf lists the operations principal may call, named as in the
// OpenAPI contract. It applies the same rules as checkAccess, so what the
// dashboard offers cannot drift from what the API allows (ADR-0010).
func permissionsOf(principal Principal) []restapi.Permission {
	permissions := make([]restapi.Permission, 0, len(accessRules))
	for operationID, rule := range accessRules {
		if principal.hasAnyRole(rule.roles) && (!rule.tenantScoped || principal.TenantID != uuid.Nil) {
			permissions = append(permissions, restapi.Permission(contractName(operationID)))
		}
	}
	slices.Sort(permissions)
	return permissions
}

// contractName turns a generated handler name into the operationId it was
// generated from: GetCurrentUser becomes getCurrentUser.
func contractName(operationID string) string {
	first, size := utf8.DecodeRuneInString(operationID)
	return string(unicode.ToLower(first)) + operationID[size:]
}
