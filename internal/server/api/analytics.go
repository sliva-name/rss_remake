package api

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/core/asset"
	"dataguard/internal/core/audit"
	"dataguard/internal/gen/restapi"
)

const (
	defaultPeriod      = 7 * 24 * time.Hour
	defaultCoverageHrs = 24
	maxCoverageHrs     = 720
	defaultEventLimit  = 100
	maxEventLimit      = 500
	typeAuthentication = "EVENT_TYPE_AUTHENTICATION"
)

// period applies the default of the last week, so no report scans all history by
// accident.
func period(from, to *time.Time) (time.Time, time.Time) {
	end := time.Now().UTC()
	if to != nil {
		end = *to
	}
	if from != nil {
		return *from, end
	}
	return end.Add(-defaultPeriod), end
}

// tableMatch lists the names events may use for the table: its current name and
// every name it had before a rename, all in the schema.table form events carry.
func tableMatch(table *asset.TableView) *audit.TableMatch {
	match := &audit.TableMatch{Names: []string{table.Schema + "." + table.Name}}
	for _, rename := range table.Renames {
		match.Names = append(match.Names, table.Schema+"."+rename.OldName)
	}
	for _, column := range table.Columns {
		match.ColumnIDs = append(match.ColumnIDs, column.ID)
	}
	return match
}

func (s *Server) ListAuditEvents(ctx context.Context, request restapi.ListAuditEventsRequestObject) (restapi.ListAuditEventsResponseObject, error) {
	params := request.Params
	limit, err := parameter("limit", params.Limit, defaultEventLimit, 1, maxEventLimit)
	if err != nil {
		return nil, err
	}
	offset, err := parameter("offset", params.Offset, 0, 0, maxOffset)
	if err != nil {
		return nil, err
	}
	from, to := period(params.From, params.To)
	if params.To == nil {
		// Time parameters reach ClickHouse with second precision, so "until now"
		// would cut off the newest second of events.
		to = time.Time{}
	}
	filter := audit.Filter{
		From: from, To: to,
		Limit:     limit,
		Offset:    offset,
		Principal: stringValue(params.Principal),
		Category:  stringValue(params.Category),
		Type:      stringValue(params.EventType),
	}
	if params.SourceId != nil {
		filter.SourceID = *params.SourceId
	}
	if params.ColumnId != nil {
		filter.ColumnID = *params.ColumnId
	}
	if params.TableId != nil {
		table, err := s.catalog.GetTable(ctx, tenantOf(ctx), *params.TableId)
		if err != nil {
			return nil, err
		}
		filter.Table = tableMatch(&table)
		if filter.SourceID == uuid.Nil {
			filter.SourceID = table.SourceID
		} else if filter.SourceID != table.SourceID {
			return restapi.ListAuditEvents200JSONResponse{Items: []restapi.AuditEvent{}, TotalExact: true}, nil
		}
	}
	if params.IncludeLogins == nil || !*params.IncludeLogins {
		filter.ExcludeType = typeAuthentication
	}
	if params.IncludeScanner == nil || !*params.IncludeScanner {
		sources, err := s.fleet.ListSources(ctx, tenantOf(ctx))
		if err != nil {
			return nil, err
		}
		for _, source := range sources {
			filter.ExcludeAccounts = append(filter.ExcludeAccounts, audit.SourceAccount{SourceID: source.ID, Principal: source.Username})
		}
	}
	events, total, err := s.events.Search(ctx, tenantOf(ctx), filter)
	if err != nil {
		return nil, err
	}
	page := restapi.AuditEventPage{
		Total: int64(min(total, audit.CountLimit)), TotalExact: total <= audit.CountLimit,
		Items: make([]restapi.AuditEvent, 0, len(events)),
	}
	for i := range events {
		page.Items = append(page.Items, toAuditEvent(&events[i]))
	}
	return restapi.ListAuditEvents200JSONResponse(page), nil
}

func toAuditEvent(event *audit.Event) restapi.AuditEvent {
	converted := restapi.AuditEvent{
		Id: event.ID, Time: event.Time, Type: event.Type, SourceId: event.SourceID,
		DatabasePrincipal: event.DatabasePrincipal, ApplicationPrincipal: event.ApplicationPrincipal,
		IdentityConfidence: event.IdentityConfidence, Operation: event.Operation, Tables: event.Tables,
		Columns: event.Columns, Categories: event.Categories, QueryFingerprint: event.QueryFingerprint,
		ExecutionStatus: event.ExecutionStatus, ErrorCode: event.ErrorCode, EvidenceLevel: event.EvidenceLevel,
		ObjectResolution: event.ObjectResolution, GapReason: event.GapReason,
	}
	if event.GapLostEvents != nil {
		lost := int64(*event.GapLostEvents)
		converted.GapLostEvents = &lost
	}
	return converted
}

func (s *Server) GetAuditCoverage(ctx context.Context, request restapi.GetAuditCoverageRequestObject) (restapi.GetAuditCoverageResponseObject, error) {
	hours, err := parameter("windowHours", request.Params.WindowHours, defaultCoverageHrs, 1, maxCoverageHrs)
	if err != nil {
		return nil, err
	}
	rows, err := s.coverage.Report(ctx, tenantOf(ctx), time.Duration(hours)*time.Hour)
	if err != nil {
		return nil, err
	}
	response := make(restapi.GetAuditCoverage200JSONResponse, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		item := restapi.CoverageRow{
			SourceId: row.SourceID, SourceKey: row.SourceKey, Engine: row.Engine,
			Status: restapi.CoverageRowStatus(row.Status), Reason: row.Reason, ReadsAudited: row.ReadsAudited,
			Statements: int64(row.Statements), Gaps: int64(row.Gaps), LostEvents: row.LostEvents,
			LastEventAt: row.LastEvent, PositionReadAt: row.PositionRead, ColumnsShare: row.ColumnsShare,
			VerifiedShare: row.VerifiedShare, PrincipalShare: row.PrincipalShare,
		}
		if row.LastScan != nil {
			item.LastScanStatus = &row.LastScan.Status
			item.LastScanAt = row.LastScan.FinishedAt
		}
		response = append(response, item)
	}
	return response, nil
}

func (s *Server) GetAccessSummary(ctx context.Context, request restapi.GetAccessSummaryRequestObject) (restapi.GetAccessSummaryResponseObject, error) {
	from, to := period(request.Params.From, request.Params.To)
	summary, err := s.events.Summarize(ctx, tenantOf(ctx), from, to)
	if err != nil {
		return nil, err
	}
	return restapi.GetAccessSummary200JSONResponse{
		Events: int64(summary.Events), SensitiveEvents: int64(summary.SensitiveEvents),
		FailedEvents: int64(summary.FailedEvents), Principals: int64(summary.Principals), Gaps: int64(summary.Gaps),
	}, nil
}

// maxTimeline bounds the hourly series: a quarter is about 2 200 points.
const maxTimeline = 93 * 24 * time.Hour

func (s *Server) GetAccessTimeline(ctx context.Context, request restapi.GetAccessTimelineRequestObject) (restapi.GetAccessTimelineResponseObject, error) {
	from, to := period(request.Params.From, request.Params.To)
	if !from.Before(to) || to.Sub(from) > maxTimeline {
		return nil, fmt.Errorf("%w: the window must be positive and at most 93 days", errInvalidParameter)
	}
	hours, err := s.events.Timeline(ctx, tenantOf(ctx), from, to)
	if err != nil {
		return nil, err
	}
	response := make(restapi.GetAccessTimeline200JSONResponse, 0, len(hours))
	for _, hour := range hours {
		response = append(response, restapi.TimelinePoint{
			Hour: hour.Start, Events: int64(hour.Events), SensitiveEvents: int64(hour.SensitiveEvents), FailedEvents: int64(hour.FailedEvents),
		})
	}
	return response, nil
}

func (s *Server) ListAccessByPrincipal(ctx context.Context, request restapi.ListAccessByPrincipalRequestObject) (restapi.ListAccessByPrincipalResponseObject, error) {
	from, to := period(request.Params.From, request.Params.To)
	filter := audit.PrincipalFilter{Category: stringValue(request.Params.Category)}
	if request.Params.ColumnId != nil {
		filter.ColumnID = *request.Params.ColumnId
	}
	groups, err := s.events.ByPrincipal(ctx, tenantOf(ctx), from, to, filter)
	if err != nil {
		return nil, err
	}
	response := make(restapi.ListAccessByPrincipal200JSONResponse, 0, len(groups))
	for i := range groups {
		item := &groups[i]
		response = append(response, restapi.PrincipalAccess{
			DatabasePrincipal: item.DatabasePrincipal, ApplicationPrincipal: item.ApplicationPrincipal,
			IdentityConfidence: item.IdentityConfidence, Events: int64(item.Events),
			SensitiveEvents: int64(item.SensitiveEvents), Categories: item.Categories,
			Sources: int64(item.Sources), LastAccess: item.LastAccess,
		})
	}
	return response, nil
}

func (s *Server) ListAccessByCategory(ctx context.Context, request restapi.ListAccessByCategoryRequestObject) (restapi.ListAccessByCategoryResponseObject, error) {
	from, to := period(request.Params.From, request.Params.To)
	groups, err := s.events.ByCategory(ctx, tenantOf(ctx), from, to)
	if err != nil {
		return nil, err
	}
	response := make(restapi.ListAccessByCategory200JSONResponse, 0, len(groups))
	for i := range groups {
		item := &groups[i]
		response = append(response, restapi.CategoryAccess{
			Category: item.Category, Events: int64(item.Events), Principals: int64(item.Principals),
			Sources: int64(item.Sources), LastAccess: item.LastAccess,
		})
	}
	return response, nil
}
