// Package ir is the dialect-neutral form of a query. It has no field for a
// literal value, so anything derived from it, such as a fingerprint, cannot
// contain data even if a frontend has a bug.
package ir

// Kind classifies a statement.
type Kind int

const (
	KindOther Kind = iota
	KindSelect
	KindInsert
	KindUpdate
	KindDelete
	KindMerge
	KindDDL
	KindDCL
)

// Name is a possibly qualified table name as written in the query.
type Name struct {
	Catalog string `json:"catalog,omitempty"`
	Schema  string `json:"schema,omitempty"`
	Table   string `json:"table"`
}

// ColumnRef is a column reference as written. Qualifier is an alias or a table.
type ColumnRef struct {
	Qualifier string `json:"qualifier,omitempty"`
	Name      string `json:"name"`
}

// Projection is one item of a select list.
type Projection struct {
	Alias string `json:"alias,omitempty"`
	// Star marks * or qualifier.*; StarQualifier is empty for a bare star.
	Star          bool        `json:"star,omitempty"`
	StarQualifier string      `json:"star_qualifier,omitempty"`
	Refs          []ColumnRef `json:"refs,omitempty"`
}

// Source is one item of a FROM clause.
type Source struct {
	Alias string `json:"alias,omitempty"`
	Table *Name  `json:"table,omitempty"`
	Query *Query `json:"query,omitempty"`
	// Columns renames the outputs of a derived table.
	Columns []string `json:"columns,omitempty"`
	// Opaque is a source whose columns cannot be known, such as a table function.
	Opaque bool `json:"opaque,omitempty"`
}

// CTE is a common table expression.
type CTE struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns,omitempty"`
	Query   *Query   `json:"query"`
}

// Query is one scope: a SELECT, or the search part of an UPDATE or DELETE.
type Query struct {
	CTEs        []CTE        `json:"ctes,omitempty"`
	Sources     []Source     `json:"sources,omitempty"`
	Projections []Projection `json:"projections,omitempty"`
	// Refs are columns used outside the select list: WHERE, JOIN, GROUP BY and so
	// on. They count as access, because a filter reveals what it matches.
	Refs []ColumnRef `json:"refs,omitempty"`
	// Subqueries are nested scopes that may see this one.
	Subqueries []*Query `json:"subqueries,omitempty"`
	// Arms are the other branches of UNION, INTERSECT and EXCEPT.
	Arms []*Query `json:"arms,omitempty"`
}

// Statement is one parsed statement.
type Statement struct {
	Kind Kind `json:"kind"`
	// Query holds everything that is read.
	Query *Query `json:"query,omitempty"`
	// Target is the table being written. Written lists its columns; AllColumns is
	// set when the statement writes whole rows without naming them.
	Target     *Name    `json:"target,omitempty"`
	Written    []string `json:"written,omitempty"`
	AllColumns bool     `json:"all_columns,omitempty"`
	// Definition is the body of CREATE VIEW. It is kept apart from Query because
	// creating a view reads nothing; the body matters only when expanding the view.
	Definition *Query `json:"definition,omitempty"`
	// Dynamic means the real work is hidden from analysis: a procedure call or
	// EXEC. The resolver reports such a statement as unresolved.
	Dynamic bool `json:"dynamic,omitempty"`
}

// Frontend parses one dialect. It must not print or return query text, because
// that text contains literals.
type Frontend interface {
	Parse(text string) ([]Statement, error)
}
