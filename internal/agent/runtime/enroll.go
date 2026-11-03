package runtime

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"dataguard/internal/agent/center"
	"dataguard/internal/agent/config"
	"dataguard/internal/agent/identity"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/pki"
)

// Enroll registers this agent once. The private key is generated here and is
// never sent; only the CSR proves possession of it. Existing state is checked
// first, so a refused enrollment does not spend the one-time token.
func Enroll(ctx context.Context, settings *config.Config, token, version string) error {
	if enrolled, err := identity.Enrolled(settings.StateDir); err != nil {
		return err
	} else if enrolled {
		return identity.ErrAlreadyEnrolled
	}
	csr, key, err := pki.NewCSR()
	if err != nil {
		return err
	}
	response, err := center.Enroll(ctx, settings.Center.URL, settings.Center.CAFile, &agentv1.EnrollRequest{
		EnrollmentToken: token, CsrPem: csr, AgentVersion: version,
	})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	tenantID, err := uuid.Parse(response.GetTenantId())
	if err != nil {
		return fmt.Errorf("parse tenant id: %w", err)
	}
	agentID, err := uuid.Parse(response.GetAgentId())
	if err != nil {
		return fmt.Errorf("parse agent id: %w", err)
	}
	return identity.Save(settings.StateDir, identity.Enrollment{
		TenantID: tenantID, AgentID: agentID, KeyPEM: key,
		CertificatePEM:  response.GetCertificatePem(),
		CACertificate:   response.GetCaCertificatePem(),
		PolicyPublicKey: response.GetPolicyPublicKey(),
	})
}
