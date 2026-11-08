package api

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"dataguard/internal/core/fleet"
	"dataguard/internal/gen/restapi"
)

// principalSearchWindow is how far back principals are looked for: names
// come from events, and older ones are in reports, not in a search box.
const principalSearchWindow = 30 * 24 * time.Hour

// Search answers the global search box. A group of results is filled only when
// the caller may open that kind of object, by the same rules as the object's
// own operation, so search never reveals what its page would refuse.
func (s *Server) Search(ctx context.Context, request restapi.SearchRequestObject) (restapi.SearchResponseObject, error) {
	text := strings.TrimSpace(request.Params.Q)
	if length := utf8.RuneCountInString(text); length < minSearchRunes || length > maxSearchRunes {
		return nil, fmt.Errorf("%w: q must be %d..%d characters", errInvalidParameter, minSearchRunes, maxSearchRunes)
	}
	tenantID := tenantOf(ctx)
	principals, err := s.searchPrincipals(ctx, tenantID, text)
	if err != nil {
		return nil, err
	}
	sources, keys, err := s.searchSources(ctx, tenantID, text)
	if err != nil {
		return nil, err
	}
	tables, columns, err := s.searchCatalog(ctx, tenantID, text, keys)
	if err != nil {
		return nil, err
	}
	return restapi.Search200JSONResponse(restapi.SearchResult{Sources: sources, Tables: tables, Columns: columns, Principals: principals}), nil
}

func (s *Server) searchPrincipals(ctx context.Context, tenantID uuid.UUID, text string) ([]restapi.PrincipalHit, error) {
	hits := []restapi.PrincipalHit{}
	if checkAccess(ctx, "ListAccessByPrincipal") != nil {
		return hits, nil
	}
	scanners, err := s.scannerAccounts(ctx)
	if err != nil {
		return nil, err
	}
	matches, err := s.events.MatchPrincipals(ctx, tenantID, text, time.Now().Add(-principalSearchWindow), scanners, searchGroupLimit)
	if err != nil {
		return nil, err
	}
	for _, match := range matches {
		hits = append(hits, restapi.PrincipalHit{
			DatabasePrincipal: match.DatabasePrincipal, ApplicationPrincipal: match.ApplicationPrincipal, Events: int64(match.Events),
		})
	}
	return hits, nil
}

// searchSources also returns the names of all readable sources, which place
// tables and columns even when the sources themselves cannot be opened.
func (s *Server) searchSources(ctx context.Context, tenantID uuid.UUID, text string) ([]restapi.SearchHit, map[uuid.UUID]string, error) {
	hits, keys := []restapi.SearchHit{}, map[uuid.UUID]string{}
	if checkAccess(ctx, "ListSources") != nil {
		return hits, keys, nil
	}
	sources, err := s.fleet.ListSources(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	for _, source := range sources {
		keys[source.ID] = source.Key
	}
	if checkAccess(ctx, "GetSource") == nil {
		hits = matchingSources(sources, text)
	}
	return hits, keys, nil
}

func (s *Server) searchCatalog(ctx context.Context, tenantID uuid.UUID, text string, keys map[uuid.UUID]string) (tables, columns []restapi.SearchHit, err error) {
	tables, columns = []restapi.SearchHit{}, []restapi.SearchHit{}
	wantTables := checkAccess(ctx, "GetCatalogTable") == nil
	wantColumns := checkAccess(ctx, "GetCatalogColumn") == nil
	if !wantTables && !wantColumns {
		return tables, columns, nil
	}
	matches, err := s.catalog.Search(ctx, tenantID, text, searchGroupLimit)
	if err != nil {
		return nil, nil, err
	}
	if wantTables {
		for _, table := range matches.Tables {
			tables = append(tables, restapi.SearchHit{
				Id: table.ID, Name: table.Name, Context: place(keys[table.SourceID], table.Database, table.Schema),
			})
		}
	}
	if wantColumns {
		for _, column := range matches.Columns {
			categories := orEmpty(column.Categories)
			columns = append(columns, restapi.SearchHit{
				Id: column.ID, Name: column.Name, Context: place(keys[column.SourceID], column.Schema, column.Table), Categories: &categories,
			})
		}
	}
	return tables, columns, nil
}

func matchingSources(sources []fleet.Source, text string) []restapi.SearchHit {
	needle := strings.ToLower(text)
	hits := []restapi.SearchHit{}
	for _, source := range sources {
		if len(hits) == searchGroupLimit {
			break
		}
		if strings.Contains(strings.ToLower(source.Key), needle) || strings.Contains(strings.ToLower(source.Host), needle) {
			hits = append(hits, restapi.SearchHit{Id: source.ID, Name: source.Key, Context: fmt.Sprintf("%s:%d/%s", source.Host, source.Port, source.Database)})
		}
	}
	return hits
}

// place joins the non-empty parts of where an object is.
func place(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " › ")
}
