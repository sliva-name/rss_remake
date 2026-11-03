package api

import (
	"context"

	"dataguard/internal/core/asset"
	"dataguard/internal/core/policy"
	"dataguard/internal/core/scan"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/gen/restapi"
)

const (
	defaultScanLimit    = 50
	defaultCatalogLimit = 100
)

func orDefault(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

func (s *Server) ListScans(ctx context.Context, request restapi.ListScansRequestObject) (restapi.ListScansResponseObject, error) {
	jobs, err := s.scans.List(ctx, tenantOf(ctx), orDefault(request.Params.Limit, defaultScanLimit))
	if err != nil {
		return nil, err
	}
	response := make(restapi.ListScans200JSONResponse, 0, len(jobs))
	for _, job := range jobs {
		response = append(response, toScan(job))
	}
	return response, nil
}

func (s *Server) RequestScan(ctx context.Context, request restapi.RequestScanRequestObject) (restapi.RequestScanResponseObject, error) {
	principal, _ := principalFrom(ctx)
	job, err := s.scans.Request(ctx, principal.TenantID, request.Body.SourceId, principal.Subject)
	if err != nil {
		return nil, err
	}
	return restapi.RequestScan201JSONResponse(toScan(job)), nil
}

func toScan(job scan.Job) restapi.Scan {
	return restapi.Scan{
		Id: job.ID, SourceId: job.SourceID, Status: restapi.ScanStatus(job.Status), RequestedBy: job.RequestedBy,
		FailureCode: job.FailureCode, CreatedAt: job.CreatedAt, StartedAt: job.StartedAt, FinishedAt: job.FinishedAt,
	}
}

func (s *Server) ListCatalogColumns(ctx context.Context, request restapi.ListCatalogColumnsRequestObject) (restapi.ListCatalogColumnsResponseObject, error) {
	filter := asset.CatalogFilter{
		Limit:  orDefault(request.Params.Limit, defaultCatalogLimit),
		Offset: orDefault(request.Params.Offset, 0),
	}
	if request.Params.SourceId != nil {
		filter.SourceID = *request.Params.SourceId
	}
	if request.Params.Category != nil {
		filter.Category = *request.Params.Category
	}
	entries, total, err := s.catalog.ListCatalog(ctx, tenantOf(ctx), filter)
	if err != nil {
		return nil, err
	}
	page := restapi.CatalogPage{Total: total, Items: make([]restapi.CatalogColumn, 0, len(entries))}
	for i := range entries {
		page.Items = append(page.Items, toCatalogColumn(&entries[i]))
	}
	return restapi.ListCatalogColumns200JSONResponse(page), nil
}

func toCatalogColumn(entry *asset.CatalogEntry) restapi.CatalogColumn {
	return restapi.CatalogColumn{
		ColumnId: entry.ColumnID, TableId: entry.TableID, SourceId: entry.SourceID, Database: entry.Database,
		Schema: entry.Schema, Table: entry.Table, Column: entry.Column, NativeType: entry.NativeType,
		CategoryId: entry.CategoryID, Confidence: entry.Confidence, NameMatch: entry.NameMatch,
		ContextMatch: entry.ContextMatch, FormatRatio: entry.FormatRatio, ChecksumRatio: entry.ChecksumRatio,
		RowsInspected: entry.RowsInspected, RowsNonNull: entry.RowsNonNull, RowsMatched: entry.RowsMatched,
		UniqueEstimate: entry.UniqueEstimate, SamplingMethod: entry.SamplingMethod, UpdatedAt: entry.UpdatedAt,
	}
}

func (s *Server) GetCatalogSummary(ctx context.Context, _ restapi.GetCatalogSummaryRequestObject) (restapi.GetCatalogSummaryResponseObject, error) {
	counts, err := s.catalog.SummarizeCatalog(ctx, tenantOf(ctx))
	if err != nil {
		return nil, err
	}
	response := make(restapi.GetCatalogSummary200JSONResponse, 0, len(counts))
	for _, item := range counts {
		response = append(response, restapi.CategoryInventory{Category: item.Category, Columns: item.Columns, Tables: item.Tables})
	}
	return response, nil
}

func (s *Server) ListCatalogChanges(ctx context.Context, request restapi.ListCatalogChangesRequestObject) (restapi.ListCatalogChangesResponseObject, error) {
	entries, err := s.catalog.ListHistory(ctx, tenantOf(ctx), orDefault(request.Params.Limit, defaultScanLimit))
	if err != nil {
		return nil, err
	}
	response := make(restapi.ListCatalogChanges200JSONResponse, 0, len(entries))
	for _, entry := range entries {
		item := restapi.CatalogChange{
			OccurredAt: entry.OccurredAt, Kind: entry.Kind, TableId: entry.TableID, TableName: entry.TableName, SourceKey: entry.SourceKey,
			ColumnId: entry.ColumnID, CategoryId: entry.CategoryID,
		}
		if entry.ColumnName != "" {
			item.ColumnName = &entry.ColumnName
		}
		response = append(response, item)
	}
	return response, nil
}

func (s *Server) GetPolicy(ctx context.Context, _ restapi.GetPolicyRequestObject) (restapi.GetPolicyResponseObject, error) {
	signed, err := s.policies.Latest(ctx, tenantOf(ctx))
	if err != nil {
		return nil, err
	}
	decoded, err := policy.Decode(signed)
	if err != nil {
		return nil, err
	}
	return restapi.GetPolicy200JSONResponse(toPolicy(decoded)), nil
}

func (s *Server) PublishPolicy(ctx context.Context, request restapi.PublishPolicyRequestObject) (restapi.PublishPolicyResponseObject, error) {
	principal, _ := principalFrom(ctx)
	detectors := make([]*agentv1.CustomDetector, 0, len(request.Body.CustomDetectors))
	for _, detector := range request.Body.CustomDetectors {
		detectors = append(detectors, &agentv1.CustomDetector{
			CategoryId:   detector.CategoryId,
			ValuePattern: stringValue(detector.ValuePattern),
			NamePattern:  stringValue(detector.NamePattern),
		})
	}
	budget := fromBudget(request.Body.ScanBudget)
	version, err := s.policies.Publish(ctx, principal.TenantID, principal.Subject, detectors, budget)
	if err != nil {
		return nil, err
	}
	return restapi.PublishPolicy201JSONResponse(toPolicy(&agentv1.Policy{
		Version: version, CustomDetectors: detectors, DefaultBudget: budget,
	})), nil
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func fromBudget(budget *restapi.ScanBudget) *agentv1.ScanBudget {
	if budget == nil {
		return nil
	}
	converted := &agentv1.ScanBudget{}
	if budget.MaxDurationSeconds != nil {
		converted.MaxDurationSeconds = uint32(*budget.MaxDurationSeconds)
	}
	if budget.MaxRowsPerTable != nil {
		converted.MaxRowsPerTable = uint64(*budget.MaxRowsPerTable)
	}
	if budget.MaxBytesPerTable != nil {
		converted.MaxBytesPerTable = uint64(*budget.MaxBytesPerTable)
	}
	if budget.MaxConnections != nil {
		converted.MaxConnections = uint32(*budget.MaxConnections)
	}
	if budget.MaxRowsPerSecond != nil {
		converted.MaxRowsPerSecond = uint32(*budget.MaxRowsPerSecond)
	}
	return converted
}

func toPolicy(source *agentv1.Policy) restapi.Policy {
	detectors := make([]restapi.CustomDetector, 0, len(source.GetCustomDetectors()))
	for _, detector := range source.GetCustomDetectors() {
		item := restapi.CustomDetector{CategoryId: detector.GetCategoryId()}
		if pattern := detector.GetValuePattern(); pattern != "" {
			item.ValuePattern = &pattern
		}
		if pattern := detector.GetNamePattern(); pattern != "" {
			item.NamePattern = &pattern
		}
		detectors = append(detectors, item)
	}
	policyView := restapi.Policy{Version: int64(source.GetVersion()), CustomDetectors: detectors}
	if budget := source.GetDefaultBudget(); budget != nil {
		seconds, rows, size, connections, speed := int(budget.GetMaxDurationSeconds()), int64(budget.GetMaxRowsPerTable()),
			int64(budget.GetMaxBytesPerTable()), int(budget.GetMaxConnections()), int(budget.GetMaxRowsPerSecond())
		policyView.ScanBudget = &restapi.ScanBudget{
			MaxDurationSeconds: &seconds, MaxRowsPerTable: &rows, MaxBytesPerTable: &size,
			MaxConnections: &connections, MaxRowsPerSecond: &speed,
		}
	}
	return policyView
}
