package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/core/audit"
	"dataguard/internal/core/policy"
	"dataguard/internal/core/preference"
	"dataguard/internal/core/risk"
	"dataguard/internal/gen/restapi"
)

func ownerOf(ctx context.Context) preference.Owner {
	principal, _ := principalFrom(ctx)
	return preference.Owner{TenantID: principal.TenantID, Subject: principal.Subject}
}

func (s *Server) GetPreference(ctx context.Context, request restapi.GetPreferenceRequestObject) (restapi.GetPreferenceResponseObject, error) {
	value, err := s.preferences.Get(ctx, ownerOf(ctx), string(request.Key))
	if err != nil {
		return nil, err
	}
	if value == nil {
		return restapi.GetPreference200JSONResponse{}, nil
	}
	return restapi.GetPreference200JSONResponse{Value: value}, nil
}

func (s *Server) SavePreference(ctx context.Context, request restapi.SavePreferenceRequestObject) (restapi.SavePreferenceResponseObject, error) {
	encoded, err := json.Marshal(request.Body.Value)
	if err != nil {
		return nil, errors.Join(preference.ErrInvalid, err)
	}
	if err := s.preferences.Put(ctx, ownerOf(ctx), string(request.Key), encoded); err != nil {
		return nil, err
	}
	return restapi.SavePreference204Response{}, nil
}

// maxExport bounds one CSV: about 40 MB, enough for an auditor's selection and
// small enough not to become a way to copy the whole log.
const maxExport = 100_000

var exportHeader = []string{
	"Время (UTC)", "Тип", "Источник", "Учётная запись СУБД", "Пользователь приложения", "Как установлен",
	"Операция", "Таблицы", "Колонки", "Категории", "Исход", "Код ошибки", "Доказательство", "Разбор",
	"Отпечаток запроса", "Сессия", "Транзакция", "Идентификатор события",
}

// utf8BOM makes spreadsheet programs read the file as UTF-8 and show Cyrillic.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// cell keeps a spreadsheet from reading a value as a formula: names and codes
// come from databases the platform does not control.
func cell(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}

func (s *Server) ExportAuditEvents(ctx context.Context, request restapi.ExportAuditEventsRequestObject) (restapi.ExportAuditEventsResponseObject, error) {
	params := request.Params
	filter, err := s.eventFilter(ctx, eventQuery{
		SourceID: params.SourceId, TableID: params.TableId, ColumnID: params.ColumnId,
		Principal: params.Principal, Category: params.Category, Type: params.EventType, SessionID: params.SessionId,
		IncludeLogins: params.IncludeLogins, IncludeScanner: params.IncludeScanner, From: params.From, To: params.To,
	})
	empty := errors.Is(err, errNothingMatches)
	if err != nil && !empty {
		return nil, err
	}
	tenantID := tenantOf(ctx)
	var total uint64
	if !empty {
		if total, err = s.events.Count(ctx, tenantID, filter, maxExport+1); err != nil {
			return nil, err
		}
	}
	sources, err := s.fleet.ListSources(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	keys := make(map[uuid.UUID]string, len(sources))
	for _, source := range sources {
		keys[source.ID] = source.Key
	}

	reader, writer := io.Pipe()
	go func() {
		out := csv.NewWriter(writer)
		_, err := writer.Write(utf8BOM)
		if err == nil {
			err = out.Write(exportHeader)
		}
		if err == nil && !empty {
			err = s.events.Stream(ctx, tenantID, filter, maxExport, func(event *audit.Event) error {
				return out.Write([]string{
					event.Time.UTC().Format(time.RFC3339), event.Type, cell(keys[event.SourceID]), cell(event.DatabasePrincipal),
					cell(event.ApplicationPrincipal), event.IdentityConfidence, event.Operation, cell(strings.Join(event.Tables, ", ")),
					cell(strings.Join(event.Columns, ", ")), strings.Join(event.Categories, ", "), event.ExecutionStatus,
					cell(event.ErrorCode), event.EvidenceLevel, event.ObjectResolution, event.QueryFingerprint, cell(event.SessionID),
					cell(event.TransactionID), event.ID.String(),
				})
			})
		}
		out.Flush()
		writer.CloseWithError(errors.Join(err, out.Error()))
	}()
	truncated := total > maxExport
	return restapi.ExportAuditEvents200TextcsvResponse{Body: reader, Headers: restapi.ExportAuditEvents200ResponseHeaders{XDataguardTruncated: &truncated}}, nil
}

func (s *Server) ListPolicyVersions(ctx context.Context, _ restapi.ListPolicyVersionsRequestObject) (restapi.ListPolicyVersionsResponseObject, error) {
	history, err := s.policies.History(ctx, tenantOf(ctx))
	if err != nil {
		return nil, err
	}
	response := make(restapi.ListPolicyVersions200JSONResponse, 0, len(history))
	for i := range history {
		decoded, err := policy.Decode(history[i].Signed)
		if err != nil {
			return nil, err
		}
		response = append(response, restapi.PolicyVersion{
			Version: int64(history[i].Version), CreatedBy: history[i].CreatedBy, CreatedAt: history[i].CreatedAt,
			CustomDetectors: len(decoded.GetCustomDetectors()), HasScanBudget: decoded.GetDefaultBudget() != nil,
		})
	}
	return response, nil
}

func (s *Server) GetPolicyVersion(ctx context.Context, request restapi.GetPolicyVersionRequestObject) (restapi.GetPolicyVersionResponseObject, error) {
	if request.Version < 1 {
		return nil, errInvalidParameter
	}
	signed, err := s.policies.Version(ctx, tenantOf(ctx), uint64(request.Version))
	if err != nil {
		return nil, err
	}
	decoded, err := policy.Decode(signed)
	if err != nil {
		return nil, err
	}
	return restapi.GetPolicyVersion200JSONResponse(toPolicy(decoded)), nil
}

// signalTTL is how long computed signals are served again. They compare a day
// with a month, so minutes of staleness change nothing, while computing them
// reads a month of events.
const signalTTL = 5 * time.Minute

type cachedSignals struct {
	at      time.Time
	signals []risk.Signal
}

// signalCache keeps the last signals of each tenant in this server instance.
type signalCache struct {
	mu      sync.Mutex
	entries map[uuid.UUID]cachedSignals
}

func (c *signalCache) get(tenantID uuid.UUID, now time.Time) ([]risk.Signal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[tenantID]
	return entry.signals, ok && now.Sub(entry.at) < signalTTL
}

func (c *signalCache) put(tenantID uuid.UUID, at time.Time, signals []risk.Signal) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[uuid.UUID]cachedSignals{}
	}
	c.entries[tenantID] = cachedSignals{at: at, signals: signals}
}

func (s *Server) riskSignals(ctx context.Context) ([]risk.Signal, error) {
	tenantID := tenantOf(ctx)
	now := time.Now()
	if signals, fresh := s.signals.get(tenantID, now); fresh {
		return signals, nil
	}
	scanners, err := s.scannerAccounts(ctx)
	if err != nil {
		return nil, err
	}
	activity, err := s.events.Activity(ctx, tenantID, audit.ActivityWindows{
		Since: now.Add(-risk.Recent), Week: risk.SpikeBaseline, Month: risk.NewBaseline,
	}, scanners)
	if err != nil {
		return nil, err
	}
	signals := risk.Signals(activity.Recent, activity.Week, activity.Month)
	s.signals.put(tenantID, now, signals)
	return signals, nil
}

func (s *Server) ListRiskSignals(ctx context.Context, _ restapi.ListRiskSignalsRequestObject) (restapi.ListRiskSignalsResponseObject, error) {
	signals, err := s.riskSignals(ctx)
	if err != nil {
		return nil, err
	}
	response := make(restapi.ListRiskSignals200JSONResponse, 0, len(signals))
	for _, signal := range signals {
		response = append(response, restapi.RiskSignal{
			Kind: restapi.RiskSignalKind(signal.Kind), DatabasePrincipal: signal.DatabasePrincipal,
			ApplicationPrincipal: signal.ApplicationPrincipal, IdentityConfidence: signal.IdentityConfidence,
			Category: signal.Category, Observed: int64(signal.Observed), Baseline: signal.Baseline, LastSeen: signal.LastSeen,
		})
	}
	return response, nil
}
