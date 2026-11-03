// Package query turns a statement into the catalog objects it touches. Names in
// the result always come from the catalog, never from the query text, so text a
// parser mistook for an identifier cannot reach the wire.
package query

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"dataguard/internal/connector"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/query/ir"
)

// maxDepth stops views that reference each other from recursing forever.
const maxDepth = 32

// Column identifies a catalog column.
type Column struct {
	Database string
	Schema   string
	Table    string
	Name     string
}

// Table identifies a catalog table or view.
type Table struct {
	Database string
	Schema   string
	Name     string
}

// Access says how a column was used.
type Access struct {
	Read    bool
	Written bool
}

// Analysis is what is known about a statement. It holds no query text.
type Analysis struct {
	Operation   agentv1.OperationType
	Tables      []Table
	Columns     map[Column]Access
	Resolution  agentv1.ObjectResolution
	Fingerprint string
	// Internal means the statement touches no user data: session settings or
	// reads of system catalogs. It is not an access worth reporting.
	Internal bool
}

// systemSchemas are engine metadata. They are not in the catalog, so a query on
// them resolves without user columns, but it is still reported: some of them hold
// credentials.
var systemSchemas = map[string]bool{
	"information_schema": true, "pg_catalog": true, "performance_schema": true,
	"mysql": true, "sys": true,
}

type tableDefinition struct {
	table      Table
	columns    []string
	view       bool
	definition string
}

// Catalog is a local snapshot of the source's objects. View definitions stay in
// it, on the agent, because they can embed literals.
type Catalog struct {
	frontend      ir.Frontend
	foldCase      bool
	defaultSchema string
	tables        map[string]*tableDefinition
}

// NewCatalog indexes tables. foldCase follows the engine's identifier rules:
// PostgreSQL parsers already fold unquoted names, while MySQL and SQL Server
// compare them case-insensitively by default.
func NewCatalog(frontend ir.Frontend, tables []connector.Table, defaultSchema string, foldCase bool) *Catalog {
	catalog := &Catalog{
		frontend: frontend, foldCase: foldCase, defaultSchema: defaultSchema,
		tables: make(map[string]*tableDefinition, len(tables)),
	}
	for i := range tables {
		source := &tables[i]
		definition := &tableDefinition{
			table:      Table{Database: source.Database, Schema: source.Schema, Name: source.Name},
			view:       source.Kind != agentv1.TableKind_TABLE_KIND_TABLE,
			definition: source.Definition,
		}
		for _, column := range source.Columns {
			definition.columns = append(definition.columns, column.Name)
		}
		catalog.tables[catalog.key(source.Schema, source.Name)] = definition
	}
	return catalog
}

func (c *Catalog) fold(name string) string {
	if c.foldCase {
		return strings.ToLower(name)
	}
	return name
}

func (c *Catalog) key(schema, table string) string {
	return c.fold(schema) + "\x00" + c.fold(table)
}

func (c *Catalog) lookup(name *ir.Name) *tableDefinition {
	schema := name.Schema
	if schema == "" {
		schema = c.defaultSchema
	}
	return c.tables[c.key(schema, name.Table)]
}

// Analyze resolves text against the catalog. Failure to parse is a normal
// outcome, reported as unresolved: nothing about the text survives.
func (c *Catalog) Analyze(text string) Analysis {
	statements, err := c.frontend.Parse(text)
	if err != nil || len(statements) == 0 {
		return Analysis{
			Operation:  agentv1.OperationType_OPERATION_TYPE_OTHER,
			Resolution: agentv1.ObjectResolution_OBJECT_RESOLUTION_UNRESOLVED,
		}
	}
	return c.AnalyzeStatements(statements)
}

// AnalyzeStatements resolves parsed statements as one operation.
func (c *Catalog) AnalyzeStatements(statements []ir.Statement) Analysis {
	state := &resolution{catalog: c, tables: map[Table]bool{}, columns: map[Column]Access{}}
	for i := range statements {
		state.statement(&statements[i])
	}
	operation := operationOf(statements)
	dynamic := slices.ContainsFunc(statements, func(s ir.Statement) bool { return s.Dynamic })
	return Analysis{
		Operation:   operation,
		Tables:      state.sortedTables(),
		Columns:     state.columns,
		Resolution:  state.outcome(),
		Fingerprint: fingerprint(statements),
		// Only a statement that touches nothing at all is internal: SELECT 1 from a
		// health check, SET, SHOW. A function call or a system catalog read (such as
		// mysql.user with password hashes) is reported.
		Internal: !dynamic && !state.incomplete && !state.calls && !state.system && len(state.tables) == 0 &&
			isReadOrOther(operation),
	}
}

func isReadOrOther(operation agentv1.OperationType) bool {
	return operation == agentv1.OperationType_OPERATION_TYPE_OTHER ||
		operation == agentv1.OperationType_OPERATION_TYPE_SELECT
}

func operationOf(statements []ir.Statement) agentv1.OperationType {
	for i := range statements {
		if operation := operation(statements[i].Kind); operation != agentv1.OperationType_OPERATION_TYPE_OTHER {
			return operation
		}
	}
	return agentv1.OperationType_OPERATION_TYPE_OTHER
}

func operation(kind ir.Kind) agentv1.OperationType {
	switch kind {
	case ir.KindSelect:
		return agentv1.OperationType_OPERATION_TYPE_SELECT
	case ir.KindInsert:
		return agentv1.OperationType_OPERATION_TYPE_INSERT
	case ir.KindUpdate:
		return agentv1.OperationType_OPERATION_TYPE_UPDATE
	case ir.KindDelete:
		return agentv1.OperationType_OPERATION_TYPE_DELETE
	case ir.KindMerge:
		return agentv1.OperationType_OPERATION_TYPE_MERGE
	case ir.KindDDL:
		return agentv1.OperationType_OPERATION_TYPE_DDL
	case ir.KindDCL:
		return agentv1.OperationType_OPERATION_TYPE_DCL
	default:
		return agentv1.OperationType_OPERATION_TYPE_OTHER
	}
}

// fingerprint hashes the IR, which cannot hold literals, so two executions that
// differ only in parameters share one fingerprint.
func fingerprint(statements []ir.Statement) string {
	encoded, err := json.Marshal(statements)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type resolution struct {
	catalog    *Catalog
	tables     map[Table]bool
	columns    map[Column]Access
	incomplete bool
	system     bool
	calls      bool
}

func (r *resolution) outcome() agentv1.ObjectResolution {
	switch {
	case !r.incomplete:
		return agentv1.ObjectResolution_OBJECT_RESOLUTION_RESOLVED
	case len(r.tables) > 0:
		return agentv1.ObjectResolution_OBJECT_RESOLUTION_PARTIAL
	default:
		return agentv1.ObjectResolution_OBJECT_RESOLUTION_UNRESOLVED
	}
}

func (r *resolution) sortedTables() []Table {
	tables := make([]Table, 0, len(r.tables))
	for table := range r.tables {
		tables = append(tables, table)
	}
	slices.SortFunc(tables, func(a, b Table) int {
		return strings.Compare(a.Schema+"."+a.Name, b.Schema+"."+b.Name)
	})
	return tables
}

func (r *resolution) touch(columns []Column) {
	for _, column := range columns {
		access := r.columns[column]
		access.Read = true
		r.columns[column] = access
	}
}

func (r *resolution) write(column Column) {
	access := r.columns[column]
	access.Written = true
	r.columns[column] = access
}

func (r *resolution) statement(statement *ir.Statement) {
	if statement.Dynamic {
		r.incomplete = true
	}
	if statement.Target != nil {
		r.writeTarget(statement)
	}
	if statement.Query != nil {
		outputs := r.query(statement.Query, nil, map[string]*binding{}, 0)
		for _, output := range outputs {
			r.touch(output.sources)
		}
	}
}

func (r *resolution) writeTarget(statement *ir.Statement) {
	definition := r.catalog.lookup(statement.Target)
	if definition == nil {
		r.incomplete = true
		return
	}
	r.tables[definition.table] = true
	if statement.AllColumns {
		for _, name := range definition.columns {
			r.write(columnOf(definition, name))
		}
		return
	}
	for _, name := range statement.Written {
		if canonical, ok := r.columnName(definition, name); ok {
			r.write(columnOf(definition, canonical))
		} else {
			r.incomplete = true
		}
	}
}

func columnOf(definition *tableDefinition, name string) Column {
	return Column{
		Database: definition.table.Database, Schema: definition.table.Schema,
		Table: definition.table.Name, Name: name,
	}
}

func (r *resolution) columnName(definition *tableDefinition, name string) (string, bool) {
	target := r.catalog.fold(name)
	for _, column := range definition.columns {
		if r.catalog.fold(column) == target {
			return column, true
		}
	}
	return "", false
}

// output is one column produced by a scope, with the catalog columns behind it.
type output struct {
	name    string
	sources []Column
}

// binding is a name usable in a FROM clause: a source, a CTE or a table.
type binding struct {
	alias   string
	outputs []output
	// opaque means columns are unknown, so references to it cannot be verified.
	opaque bool
	// recursive marks a binding whose columns need no checking: a CTE inside its
	// own definition, where the base arm supplies them, or a system catalog.
	recursive bool
}

type scope struct {
	parent   *scope
	bindings []*binding
	aliases  []string
}

func (r *resolution) query(query *ir.Query, parent *scope, ctes map[string]*binding, depth int) []output {
	if depth > maxDepth {
		r.incomplete = true
		return nil
	}
	ctes = r.bindCTEs(query, parent, ctes, depth)
	r.calls = r.calls || query.Calls
	current := &scope{parent: parent}
	for i := range query.Sources {
		current.bindings = append(current.bindings, r.bindSource(&query.Sources[i], current, ctes, depth))
	}
	for _, projection := range query.Projections {
		if projection.Alias != "" {
			current.aliases = append(current.aliases, r.catalog.fold(projection.Alias))
		}
	}
	for _, reference := range query.Refs {
		r.touch(r.reference(current, reference))
	}
	for _, subquery := range query.Subqueries {
		for _, item := range r.query(subquery, current, ctes, depth+1) {
			r.touch(item.sources)
		}
	}
	outputs := r.projections(query, current)
	for _, arm := range query.Arms {
		outputs = mergeArm(outputs, r.query(arm, parent, ctes, depth+1))
	}
	return outputs
}

// mergeArm combines set-operation branches by position, because the column
// names of the first branch name the result.
func mergeArm(outputs, arm []output) []output {
	for i := range min(len(outputs), len(arm)) {
		outputs[i].sources = append(outputs[i].sources, arm[i].sources...)
	}
	return outputs
}

func (r *resolution) bindCTEs(query *ir.Query, parent *scope, inherited map[string]*binding, depth int) map[string]*binding {
	if len(query.CTEs) == 0 {
		return inherited
	}
	ctes := make(map[string]*binding, len(inherited)+len(query.CTEs))
	for name, item := range inherited {
		ctes[name] = item
	}
	for i := range query.CTEs {
		cte := &query.CTEs[i]
		name := r.catalog.fold(cte.Name)
		ctes[name] = &binding{alias: cte.Name, opaque: true, recursive: true}
		outputs := r.query(cte.Query, parent, ctes, depth+1)
		ctes[name] = &binding{alias: cte.Name, outputs: renameOutputs(outputs, cte.Columns)}
	}
	return ctes
}

func renameOutputs(outputs []output, names []string) []output {
	for i := range min(len(outputs), len(names)) {
		outputs[i].name = names[i]
	}
	return outputs
}

func (r *resolution) bindSource(source *ir.Source, current *scope, ctes map[string]*binding, depth int) *binding {
	alias := source.Alias
	switch {
	case source.Opaque:
		r.incomplete = true
		return &binding{alias: alias, opaque: true}
	case source.Query != nil:
		// Passing the scope lets lateral subqueries see earlier sources.
		outputs := r.query(source.Query, current, ctes, depth+1)
		return &binding{alias: alias, outputs: renameOutputs(outputs, source.Columns)}
	case source.Table != nil:
		return r.bindTable(source, ctes, depth)
	default:
		r.incomplete = true
		return &binding{alias: alias, opaque: true}
	}
}

func (r *resolution) bindTable(source *ir.Source, ctes map[string]*binding, depth int) *binding {
	alias := source.Alias
	if alias == "" {
		alias = source.Table.Table
	}
	if source.Table.Schema == "" {
		if cte, found := ctes[r.catalog.fold(source.Table.Table)]; found {
			return &binding{alias: alias, outputs: cte.outputs, opaque: cte.opaque, recursive: cte.recursive}
		}
	}
	definition := r.catalog.lookup(source.Table)
	if definition == nil {
		if systemSchemas[strings.ToLower(source.Table.Schema)] {
			r.system = true
			return &binding{alias: alias, opaque: true, recursive: true}
		}
		r.incomplete = true
		return &binding{alias: alias, opaque: true}
	}
	r.tables[definition.table] = true
	if definition.view {
		return &binding{alias: alias, outputs: r.expandView(definition, depth)}
	}
	outputs := make([]output, 0, len(definition.columns))
	for _, name := range definition.columns {
		outputs = append(outputs, output{name: name, sources: []Column{columnOf(definition, name)}})
	}
	return &binding{alias: alias, outputs: outputs}
}

// expandView maps a view's columns to the columns behind them, so reading a view
// is reported against the sensitive base columns it exposes.
func (r *resolution) expandView(definition *tableDefinition, depth int) []output {
	statements, err := r.catalog.frontend.Parse(definition.definition)
	if err != nil || len(statements) != 1 {
		r.incomplete = true
		return viewColumnsOnly(definition)
	}
	body := statements[0].Definition
	if body == nil {
		body = statements[0].Query
	}
	if body == nil {
		r.incomplete = true
		return viewColumnsOnly(definition)
	}
	return renameOutputs(r.query(body, nil, map[string]*binding{}, depth+1), definition.columns)
}

func viewColumnsOnly(definition *tableDefinition) []output {
	outputs := make([]output, 0, len(definition.columns))
	for _, name := range definition.columns {
		outputs = append(outputs, output{name: name, sources: []Column{columnOf(definition, name)}})
	}
	return outputs
}

func (r *resolution) projections(query *ir.Query, current *scope) []output {
	var outputs []output
	for i := range query.Projections {
		projection := &query.Projections[i]
		if projection.Star {
			outputs = append(outputs, r.expandStar(current, projection.StarQualifier)...)
			continue
		}
		item := output{name: projection.Alias}
		for _, reference := range projection.Refs {
			item.sources = append(item.sources, r.reference(current, reference)...)
			if item.name == "" && len(projection.Refs) == 1 {
				item.name = reference.Name
			}
		}
		outputs = append(outputs, item)
	}
	return outputs
}

func (r *resolution) expandStar(current *scope, qualifier string) []output {
	var outputs []output
	matched := false
	for _, item := range current.bindings {
		if qualifier != "" && r.catalog.fold(item.alias) != r.catalog.fold(qualifier) {
			continue
		}
		matched = true
		if item.opaque && !item.recursive {
			r.incomplete = true
		}
		outputs = append(outputs, item.outputs...)
	}
	if !matched {
		r.incomplete = true
	}
	return outputs
}

// reference finds what a name refers to, walking outwards for correlated
// subqueries. An unknown name leaves the result incomplete instead of guessing.
func (r *resolution) reference(current *scope, reference ir.ColumnRef) []Column {
	name := r.catalog.fold(reference.Name)
	qualifier := r.catalog.fold(reference.Qualifier)
	for level := current; level != nil; level = level.parent {
		if columns, found := r.inScope(level, qualifier, name); found {
			return columns
		}
	}
	r.incomplete = true
	return nil
}

func (r *resolution) inScope(level *scope, qualifier, name string) ([]Column, bool) {
	var matches [][]Column
	for _, item := range level.bindings {
		if qualifier != "" && r.catalog.fold(item.alias) != qualifier {
			continue
		}
		if item.recursive {
			return nil, true
		}
		for _, candidate := range item.outputs {
			if r.catalog.fold(candidate.name) == name {
				matches = append(matches, candidate.sources)
			}
		}
	}
	if len(matches) == 1 {
		return matches[0], true
	}
	if len(matches) > 1 {
		// An ambiguous name is rejected by the database, so it can only mean the
		// column was merged by USING: all candidates are the same value.
		return slices.Concat(matches...), true
	}
	return r.fallback(level, qualifier, name)
}

// fallback handles names that are not columns of a source: an alias of the
// select list, as in ORDER BY, or a whole-row reference to a table alias, which
// exposes every column.
func (r *resolution) fallback(level *scope, qualifier, name string) ([]Column, bool) {
	if qualifier != "" {
		return nil, false
	}
	if slices.Contains(level.aliases, name) {
		return nil, true
	}
	for _, item := range level.bindings {
		if r.catalog.fold(item.alias) == name {
			var columns []Column
			for _, candidate := range item.outputs {
				columns = append(columns, candidate.sources...)
			}
			return columns, true
		}
	}
	return nil, false
}
