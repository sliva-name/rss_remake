package api

import (
	"context"
	"net/http"

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
	"RevokeAgent":           {roles: tenantAdmins, tenantScoped: true},
	"ListSources":           {roles: tenantReaders, tenantScoped: true},
	"ListScans":             {roles: tenantReaders, tenantScoped: true},
	"RequestScan":           {roles: scanRequesters, tenantScoped: true},
	"ListCatalogColumns":    {roles: tenantReaders, tenantScoped: true},
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
