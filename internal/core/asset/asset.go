// Package asset keeps the inventory of database objects. An object gets a UUID
// on first sight and keeps it across renames, because its name is an attribute
// and the history of access to it must survive a rename.
package asset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Object statuses.
const (
	StatusActive  = "active"
	StatusRemoved = "removed"
)

// Change kinds recorded in catalog history.
const (
	ChangeTableAdded       = "TABLE_ADDED"
	ChangeTableRemoved     = "TABLE_REMOVED"
	ChangeTableRenamed     = "TABLE_RENAMED"
	ChangeColumnAdded      = "COLUMN_ADDED"
	ChangeColumnRemoved    = "COLUMN_REMOVED"
	ChangeColumnRenamed    = "COLUMN_RENAMED"
	ChangeSensitiveAdded   = "SENSITIVE_COLUMN_ADDED"
	ChangeSensitiveGone    = "SENSITIVE_COLUMN_REMOVED"
	ChangeSchemaDrift      = "SCHEMA_DRIFT_DETECTED"
	renameByFingerprint    = "structure_fingerprint"
	renameByTypeAndOrdinal = "type_and_position"
)

type Column struct {
	ID         uuid.UUID
	Name       string
	NativeType string
	Ordinal    int32
	Nullable   bool
	Status     string
}

type Table struct {
	ID          uuid.UUID
	Database    string
	Schema      string
	Name        string
	Kind        string
	Fingerprint string
	Status      string
	Columns     []Column
}

func (t *Table) key() string {
	return t.Database + "\x00" + t.Schema + "\x00" + t.Name
}

// CatalogEntry is one classified column as shown to operators.
type CatalogEntry struct {
	ColumnID       uuid.UUID
	TableID        uuid.UUID
	SourceID       uuid.UUID
	Database       string
	Schema         string
	Table          string
	Column         string
	NativeType     string
	CategoryID     string
	Confidence     float64
	NameMatch      bool
	ContextMatch   bool
	FormatRatio    float64
	ChecksumRatio  *float64
	RowsInspected  int64
	RowsNonNull    int64
	RowsMatched    int64
	UniqueEstimate int64
	SamplingMethod string
	UpdatedAt      time.Time
}

// CatalogFilter narrows a catalog listing; zero values mean no filter.
type CatalogFilter struct {
	SourceID uuid.UUID
	Category string
	Limit    int
	Offset   int
}

// HistoryEntry is one line of catalog history with names resolved.
type HistoryEntry struct {
	OccurredAt time.Time
	Kind       string
	TableID    uuid.UUID
	SourceKey  string
	TableName  string
	ColumnID   *uuid.UUID
	ColumnName string
	CategoryID string
}

// ErrNotFound means the object does not exist in the tenant.
var ErrNotFound = errors.New("not found")

// Reader answers catalog queries.
type Reader interface {
	ListCatalog(ctx context.Context, tenantID uuid.UUID, filter CatalogFilter) ([]CatalogEntry, int64, error)
	ListHistory(ctx context.Context, tenantID uuid.UUID, filter HistoryFilter) ([]HistoryEntry, error)
	SummarizeCatalog(ctx context.Context, tenantID uuid.UUID) ([]CategoryCount, error)
	ListTables(ctx context.Context, tenantID uuid.UUID, filter TableFilter) ([]TableEntry, int64, error)
	GetTable(ctx context.Context, tenantID, tableID uuid.UUID) (TableView, error)
	GetColumn(ctx context.Context, tenantID, columnID uuid.UUID) (ColumnView, error)
	Search(ctx context.Context, tenantID uuid.UUID, text string, limit int) (Matches, error)
}

// HistoryFilter narrows catalog history; zero times mean no bound.
type HistoryFilter struct {
	Limit int
	From  time.Time
	To    time.Time
}

// TableFilter narrows a table listing; zero values mean no filter.
type TableFilter struct {
	SourceID uuid.UUID
	// Query is part of the database, schema or table name, case-insensitive.
	Query         string
	Category      string
	SensitiveOnly bool
	Limit         int
	Offset        int
}

// Matches are active tables and columns whose name contains a text.
type Matches struct {
	Tables  []TableMatch
	Columns []ColumnMatch
}

type TableMatch struct {
	ID       uuid.UUID
	SourceID uuid.UUID
	Database string
	Schema   string
	Name     string
}

type ColumnMatch struct {
	ID         uuid.UUID
	SourceID   uuid.UUID
	Schema     string
	Table      string
	Name       string
	Categories []string
}

// TableEntry is one active table with how much of it is sensitive.
type TableEntry struct {
	ID               uuid.UUID
	SourceID         uuid.UUID
	Database         string
	Schema           string
	Name             string
	Kind             string
	Columns          int64
	SensitiveColumns int64
	Categories       []string
	LastSeenAt       time.Time
}

// TableView is one table with its active columns. A removed table is still
// shown: events keep referring to it.
type TableView struct {
	ID          uuid.UUID
	SourceID    uuid.UUID
	Database    string
	Schema      string
	Name        string
	Kind        string
	Status      string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	Columns     []ColumnEntry
	Renames     []RenameRecord
}

// ColumnEntry is one column of a table with its detected categories.
type ColumnEntry struct {
	ID         uuid.UUID
	Name       string
	NativeType string
	Ordinal    int32
	Nullable   bool
	Categories []string
}

// ColumnView is one column with every classification decision about it.
type ColumnView struct {
	ID              uuid.UUID
	TableID         uuid.UUID
	SourceID        uuid.UUID
	Database        string
	Schema          string
	Table           string
	Name            string
	NativeType      string
	Ordinal         int32
	Nullable        bool
	Status          string
	FirstSeenAt     time.Time
	LastSeenAt      time.Time
	Classifications []Decision
	Renames         []RenameRecord
}

// Decision is what the classifier concluded about one category of a column,
// including that it is absent.
type Decision struct {
	CategoryID     string
	Detected       bool
	Confidence     float64
	NameMatch      bool
	ContextMatch   bool
	FormatRatio    float64
	ChecksumRatio  *float64
	RowsInspected  int64
	RowsNonNull    int64
	RowsMatched    int64
	UniqueEstimate int64
	SamplingMethod string
	FirstSeenAt    time.Time
	UpdatedAt      time.Time
}

// RenameRecord is a stored rename.
type RenameRecord struct {
	OldName    string
	NewName    string
	DetectedAt time.Time
	DetectedBy string
}

// CategoryCount says how much of a category is stored.
type CategoryCount struct {
	Category string
	Columns  int64
	Tables   int64
}

// Rename is one detected name change.
type Rename struct {
	ObjectKind string
	ObjectID   uuid.UUID
	OldName    string
	NewName    string
	DetectedBy string
}

// Change is one line of catalog history.
type Change struct {
	Kind     string
	TableID  uuid.UUID
	ColumnID *uuid.UUID
}

// Plan is the outcome of reconciling a snapshot with the stored catalog.
type Plan struct {
	// Tables holds the desired state of every touched table, keyed by id.
	Tables  []Table
	Renames []Rename
	Changes []Change
}

// Fingerprint identifies a table's structure regardless of its name or of the
// order in which the catalog lists columns.
func Fingerprint(columns []Column) string {
	parts := make([]string, 0, len(columns))
	for _, column := range columns {
		parts = append(parts, column.Name+"\x00"+column.NativeType+"\x00"+strconv.FormatBool(column.Nullable))
	}
	slices.Sort(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x01")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Reconcile compares a complete snapshot with the stored tables. It is a pure
// function so rename rules can be tested without a database. Status of input
// tables is expected to be StatusActive; existing may include removed tables,
// which come back to life if they reappear under the same name.
func Reconcile(existing, snapshot []Table) Plan {
	plan := Plan{}
	byKey := make(map[string]*Table, len(existing))
	for i := range existing {
		byKey[existing[i].key()] = &existing[i]
	}

	matched := make(map[uuid.UUID]bool, len(existing))
	var unmatched []*Table
	for i := range snapshot {
		incoming := &snapshot[i]
		incoming.Fingerprint = Fingerprint(incoming.Columns)
		current, found := byKey[incoming.key()]
		if !found {
			unmatched = append(unmatched, incoming)
			continue
		}
		matched[current.ID] = true
		plan.updateTable(current, incoming)
	}

	orphans := activeOrphans(existing, matched)
	for _, incoming := range unmatched {
		if orphan := takeRenamed(&orphans, incoming); orphan != nil {
			plan.renameTable(orphan, incoming)
			continue
		}
		plan.addTable(incoming)
	}
	for _, orphan := range orphans {
		plan.removeTable(orphan)
	}
	return plan
}

func activeOrphans(existing []Table, matched map[uuid.UUID]bool) []*Table {
	var orphans []*Table
	for i := range existing {
		if !matched[existing[i].ID] && existing[i].Status == StatusActive {
			orphans = append(orphans, &existing[i])
		}
	}
	return orphans
}

// takeRenamed claims a vanished table with the same structure in the same
// schema. Two identical candidates are ambiguous, so neither is treated as a
// rename: a wrong merge would corrupt access history, a missed one only starts
// a new object.
func takeRenamed(orphans *[]*Table, incoming *Table) *Table {
	match := -1
	for i, orphan := range *orphans {
		if orphan.Schema != incoming.Schema || orphan.Database != incoming.Database || orphan.Fingerprint != incoming.Fingerprint {
			continue
		}
		if match >= 0 {
			return nil
		}
		match = i
	}
	if match < 0 {
		return nil
	}
	orphan := (*orphans)[match]
	*orphans = slices.Delete(*orphans, match, match+1)
	return orphan
}

func (p *Plan) addTable(incoming *Table) {
	created := *incoming
	created.ID = uuid.Must(uuid.NewV7())
	created.Status = StatusActive
	created.Columns = slices.Clone(incoming.Columns)
	p.Changes = append(p.Changes, Change{Kind: ChangeTableAdded, TableID: created.ID})
	for i := range created.Columns {
		created.Columns[i].ID = uuid.Must(uuid.NewV7())
		created.Columns[i].Status = StatusActive
	}
	p.Tables = append(p.Tables, created)
}

func (p *Plan) renameTable(current, incoming *Table) {
	p.Renames = append(p.Renames, Rename{
		ObjectKind: "table", ObjectID: current.ID, OldName: current.Name, NewName: incoming.Name,
		DetectedBy: renameByFingerprint,
	})
	p.Changes = append(p.Changes, Change{Kind: ChangeTableRenamed, TableID: current.ID})
	p.updateTable(current, incoming)
}

func (p *Plan) removeTable(current *Table) {
	removed := *current
	removed.Status = StatusRemoved
	removed.Columns = slices.Clone(current.Columns)
	for i := range removed.Columns {
		removed.Columns[i].Status = StatusRemoved
	}
	p.Changes = append(p.Changes, Change{Kind: ChangeTableRemoved, TableID: current.ID})
	p.Tables = append(p.Tables, removed)
}

func (p *Plan) updateTable(current, incoming *Table) {
	if current.Status == StatusActive && current.Fingerprint != incoming.Fingerprint {
		p.Changes = append(p.Changes, Change{Kind: ChangeSchemaDrift, TableID: current.ID})
	}
	updated := *incoming
	updated.ID = current.ID
	updated.Status = StatusActive
	updated.Columns = p.reconcileColumns(current, incoming)
	p.Tables = append(p.Tables, updated)
}

func (p *Plan) reconcileColumns(current, incoming *Table) []Column {
	byName := make(map[string]*Column, len(current.Columns))
	for i := range current.Columns {
		byName[current.Columns[i].Name] = &current.Columns[i]
	}
	seen := make(map[uuid.UUID]bool, len(current.Columns))
	result := make([]Column, 0, len(incoming.Columns))
	var added []Column
	for _, column := range incoming.Columns {
		stored, found := byName[column.Name]
		if !found {
			added = append(added, column)
			continue
		}
		seen[stored.ID] = true
		column.ID = stored.ID
		column.Status = StatusActive
		result = append(result, column)
	}

	var vanished []*Column
	for i := range current.Columns {
		if !seen[current.Columns[i].ID] && current.Columns[i].Status == StatusActive {
			vanished = append(vanished, &current.Columns[i])
		}
	}
	result, vanished = p.placeAdded(current.ID, result, added, vanished)
	for _, column := range vanished {
		removed := *column
		removed.Status = StatusRemoved
		id := column.ID
		p.Changes = append(p.Changes, Change{Kind: ChangeColumnRemoved, TableID: current.ID, ColumnID: &id})
		result = append(result, removed)
	}
	return result
}

func (p *Plan) placeAdded(tableID uuid.UUID, result, added []Column, vanished []*Column) ([]Column, []*Column) {
	for _, column := range added {
		index := slices.IndexFunc(vanished, func(candidate *Column) bool {
			return candidate.NativeType == column.NativeType && candidate.Ordinal == column.Ordinal
		})
		column.Status = StatusActive
		if index < 0 {
			column.ID = uuid.Must(uuid.NewV7())
			id := column.ID
			p.Changes = append(p.Changes, Change{Kind: ChangeColumnAdded, TableID: tableID, ColumnID: &id})
			result = append(result, column)
			continue
		}
		column.ID = vanished[index].ID
		id := column.ID
		p.Renames = append(p.Renames, Rename{
			ObjectKind: "column", ObjectID: id, OldName: vanished[index].Name, NewName: column.Name,
			DetectedBy: renameByTypeAndOrdinal,
		})
		p.Changes = append(p.Changes, Change{Kind: ChangeColumnRenamed, TableID: tableID, ColumnID: &id})
		vanished = slices.Delete(vanished, index, index+1)
		result = append(result, column)
	}
	return result, vanished
}
