// Package tsql parses Transact-SQL with an ANTLR grammar. This is the weakest of
// the three frontends: anything the grammar rejects is reported as unresolved.
package tsql

import (
	"errors"
	"strings"

	"github.com/antlr4-go/antlr/v4"
	parser "github.com/bytebase/parser/tsql"

	"dataguard/internal/query/ir"
)

// Frontend implements ir.Frontend.
type Frontend struct{}

var errNotParsed = errors.New("statement could not be parsed")

// errorCounter replaces ANTLR's default listener, which prints the offending
// fragment of the query to stderr.
type errorCounter struct {
	*antlr.DefaultErrorListener
	errors int
}

func (c *errorCounter) SyntaxError(antlr.Recognizer, any, int, int, string, antlr.RecognitionException) {
	c.errors++
}

// Parse returns no details on failure; they would quote the query.
func (Frontend) Parse(text string) ([]ir.Statement, error) {
	counter := &errorCounter{DefaultErrorListener: antlr.NewDefaultErrorListener()}
	lexer := parser.NewTSqlLexer(antlr.NewInputStream(text))
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(counter)
	grammar := parser.NewTSqlParser(antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel))
	grammar.RemoveErrorListeners()
	grammar.AddErrorListener(counter)

	tree := grammar.Tsql_file()
	if counter.errors > 0 {
		return nil, errNotParsed
	}
	var statements []ir.Statement
	findStatements(tree, &statements)
	if len(statements) == 0 {
		return nil, errNotParsed
	}
	return statements, nil
}

func findStatements(node antlr.Tree, statements *[]ir.Statement) {
	if statement, found := convert(node); found {
		*statements = append(*statements, statement)
		return
	}
	for _, child := range node.GetChildren() {
		findStatements(child, statements)
	}
}

func convert(node antlr.Tree) (ir.Statement, bool) {
	switch item := node.(type) {
	case *parser.Select_statement_standaloneContext:
		return ir.Statement{Kind: ir.KindSelect, Query: standalone(item)}, true
	case *parser.Insert_statementContext:
		return insert(item), true
	case *parser.Update_statementContext:
		return update(item), true
	case *parser.Delete_statementContext:
		return deletion(item), true
	case *parser.Merge_statementContext:
		return merge(item), true
	case *parser.Create_viewContext:
		return ir.Statement{Kind: ir.KindDDL, Definition: standalone(item.Select_statement_standalone())}, true
	case *parser.Execute_statementContext:
		return ir.Statement{Kind: ir.KindOther, Dynamic: true}, true
	case *parser.Security_statementContext:
		return ir.Statement{Kind: ir.KindDCL}, true
	case *parser.Ddl_clauseContext:
		for _, child := range item.GetChildren() {
			if view, ok := child.(*parser.Create_viewContext); ok {
				return convert(view)
			}
		}
		return ir.Statement{Kind: ir.KindDDL}, true
	default:
		return ir.Statement{}, false
	}
}

func standalone(item parser.ISelect_statement_standaloneContext) *ir.Query {
	query := selectStatement(item.Select_statement())
	query.CTEs = append(ctes(item.With_expression()), query.CTEs...)
	return query
}

func ctes(clause parser.IWith_expressionContext) []ir.CTE {
	if clause == nil {
		return nil
	}
	var result []ir.CTE
	for _, cte := range clause.AllCommon_table_expression() {
		item := ir.CTE{Name: identifier(cte.GetExpression_name()), Query: selectStatement(cte.GetCte_query())}
		if columns := cte.GetColumns(); columns != nil {
			for _, column := range columns.AllId_() {
				item.Columns = append(item.Columns, identifier(column))
			}
		}
		result = append(result, item)
	}
	return result
}

func selectStatement(item parser.ISelect_statementContext) *ir.Query {
	query := queryExpression(item.Query_expression())
	if order := item.Select_order_by_clause(); order != nil {
		collect(query, order)
	}
	return query
}

func queryExpression(item parser.IQuery_expressionContext) *ir.Query {
	if specification := item.Query_specification(); specification != nil {
		query := querySpecification(specification)
		if order := item.Select_order_by_clause(); order != nil {
			collect(query, order)
		}
		for _, union := range item.AllSql_union() {
			query.Arms = append(query.Arms, unionArm(union))
		}
		return query
	}
	branches := item.AllQuery_expression()
	if len(branches) == 0 {
		return &ir.Query{Sources: []ir.Source{{Opaque: true}}}
	}
	query := queryExpression(branches[0])
	for _, branch := range branches[1:] {
		query.Arms = append(query.Arms, queryExpression(branch))
	}
	return query
}

func unionArm(union parser.ISql_unionContext) *ir.Query {
	if specification := union.GetSpec(); specification != nil {
		return querySpecification(specification)
	}
	return queryExpression(union.GetOp())
}

func querySpecification(item parser.IQuery_specificationContext) *ir.Query {
	query := &ir.Query{}
	if from := item.From_table_sources(); from != nil {
		tableSources(from.Table_sources(), query)
	}
	for _, element := range item.GetColumns().AllSelect_list_elem() {
		query.Projections = append(query.Projections, projection(element, query))
	}
	if where := item.GetWhere(); where != nil {
		collect(query, where)
	}
	if group := item.Group_by_clause(); group != nil {
		collect(query, group)
	}
	if having := item.Having_clause(); having != nil {
		collect(query, having)
	}
	return query
}

func tableSources(item parser.ITable_sourcesContext, query *ir.Query) {
	for _, source := range item.AllTable_source() {
		tableSource(source, query)
	}
}

func tableSource(item parser.ITable_sourceContext, query *ir.Query) {
	sourceItem(item.Table_source_item(), query)
	for _, join := range item.AllJoin_part() {
		joinPart(join, query)
	}
}

func joinPart(item parser.IJoin_partContext, query *ir.Query) {
	switch {
	case item.Join_on() != nil:
		tableSource(item.Join_on().GetSource(), query)
		collect(query, item.Join_on().GetCond())
	case item.Cross_join() != nil:
		sourceItem(item.Cross_join().Table_source_item(), query)
	case item.Apply_() != nil:
		sourceItem(item.Apply_().GetSource(), query)
	default:
		query.Sources = append(query.Sources, ir.Source{Opaque: true})
	}
}

func sourceItem(item parser.ITable_source_itemContext, query *ir.Query) {
	switch {
	case item.Table_source() != nil:
		tableSource(item.Table_source(), query)
	case item.Full_table_name() != nil:
		query.Sources = append(query.Sources, ir.Source{Alias: aliasOf(item.As_table_alias()), Table: tableName(item.Full_table_name())})
	case item.Derived_table() != nil:
		source := ir.Source{Alias: aliasOf(item.As_table_alias()), Query: derived(item.Derived_table())}
		if columns := item.Column_alias_list(); columns != nil {
			for _, column := range columns.AllColumn_alias() {
				source.Columns = append(source.Columns, unquote(column.GetText()))
			}
		}
		query.Sources = append(query.Sources, source)
	default:
		query.Sources = append(query.Sources, ir.Source{Alias: aliasOf(item.As_table_alias()), Opaque: true})
	}
}

func derived(item parser.IDerived_tableContext) *ir.Query {
	subqueries := item.AllSubquery()
	if len(subqueries) == 0 {
		// VALUES constructors produce only literals.
		return &ir.Query{}
	}
	query := selectStatement(subqueries[0].Select_statement())
	for _, subquery := range subqueries[1:] {
		query.Arms = append(query.Arms, selectStatement(subquery.Select_statement()))
	}
	return query
}

func aliasOf(item parser.IAs_table_aliasContext) string {
	if item == nil {
		return ""
	}
	return identifier(item.Table_alias().Id_())
}

func projection(item parser.ISelect_list_elemContext, query *ir.Query) ir.Projection {
	if star := item.Asterisk(); star != nil {
		result := ir.Projection{Star: true}
		if table := star.Table_name(); table != nil {
			result.StarQualifier = identifier(table.GetTable())
		}
		return result
	}
	scratch := &ir.Query{}
	collect(scratch, item)
	query.Subqueries = append(query.Subqueries, scratch.Subqueries...)
	result := ir.Projection{Refs: scratch.Refs}
	if element := item.Expression_elem(); element != nil {
		result.Alias = expressionAlias(element)
	}
	return result
}

func expressionAlias(element parser.IExpression_elemContext) string {
	if alias := element.GetLeftAlias(); alias != nil {
		return unquote(alias.GetText())
	}
	if alias := element.As_column_alias(); alias != nil {
		return unquote(alias.Column_alias().GetText())
	}
	return ""
}

func tableName(item parser.IFull_table_nameContext) *ir.Name {
	parts := identifiers(item)
	name := &ir.Name{}
	if count := len(parts); count > 0 {
		name.Table = parts[count-1]
		if count > 1 {
			name.Schema = parts[count-2]
		}
		if count > 2 {
			name.Catalog = parts[count-3]
		}
	}
	return name
}

func identifiers(node antlr.Tree) []string {
	var parts []string
	for _, child := range node.GetChildren() {
		if id, ok := child.(*parser.Id_Context); ok {
			parts = append(parts, identifier(id))
			continue
		}
		parts = append(parts, identifiers(child)...)
	}
	return parts
}

func identifier(item parser.IId_Context) string {
	if item == nil {
		return ""
	}
	return unquote(item.GetText())
}

func unquote(text string) string {
	if len(text) >= 2 {
		switch {
		case text[0] == '[' && text[len(text)-1] == ']':
			return strings.ReplaceAll(text[1:len(text)-1], "]]", "]")
		case text[0] == '"' && text[len(text)-1] == '"', text[0] == '\'' && text[len(text)-1] == '\'':
			return text[1 : len(text)-1]
		}
	}
	return text
}

// collect walks an expression. Generated rule contexts number in the hundreds;
// only column names and nested selects matter here.
func collect(query *ir.Query, node antlr.Tree) {
	switch item := node.(type) {
	case *parser.Full_column_nameContext:
		reference := ir.ColumnRef{Name: identifier(item.GetColumn_name())}
		if table := item.Full_table_name(); table != nil {
			reference.Qualifier = tableName(table).Table
		}
		if reference.Name != "" {
			query.Refs = append(query.Refs, reference)
		}
		return
	case *parser.Select_statementContext:
		query.Subqueries = append(query.Subqueries, selectStatement(item))
		return
	}
	for _, child := range node.GetChildren() {
		collect(query, child)
	}
}

func targetName(item parser.IDdl_objectContext) *ir.Name {
	if item == nil || item.Full_table_name() == nil {
		return nil
	}
	return tableName(item.Full_table_name())
}

func insert(item *parser.Insert_statementContext) ir.Statement {
	result := ir.Statement{Kind: ir.KindInsert, Target: targetName(item.Ddl_object()), Query: &ir.Query{CTEs: ctes(item.With_expression())}}
	if columns := item.Insert_column_name_list(); columns != nil {
		for _, column := range columns.AllInsert_column_id() {
			parts := identifiers(column)
			if len(parts) > 0 {
				result.Written = append(result.Written, parts[len(parts)-1])
			}
		}
	}
	result.AllColumns = len(result.Written) == 0
	if value := item.Insert_statement_value(); value != nil {
		insertSource(value, result.Query)
	}
	return result
}

// insertSource folds INSERT ... SELECT into the read query of the statement.
func insertSource(value parser.IInsert_statement_valueContext, query *ir.Query) {
	scratch := &ir.Query{}
	collect(scratch, value)
	if len(scratch.Subqueries) == 1 {
		inner := scratch.Subqueries[0]
		inner.CTEs = append(query.CTEs, inner.CTEs...)
		*query = *inner
		return
	}
	query.Subqueries = append(query.Subqueries, scratch.Subqueries...)
	query.Refs = append(query.Refs, scratch.Refs...)
}

func update(item *parser.Update_statementContext) ir.Statement {
	target := targetName(item.Ddl_object())
	query := &ir.Query{CTEs: ctes(item.With_expression())}
	if target != nil {
		query.Sources = []ir.Source{{Table: target}}
	}
	if sources := item.Table_sources(); sources != nil {
		tableSources(sources, query)
	}
	result := ir.Statement{Kind: ir.KindUpdate, Target: target, Query: query}
	for _, assignment := range item.AllUpdate_elem() {
		if column := assignment.Full_column_name(); column != nil {
			result.Written = append(result.Written, identifier(column.GetColumn_name()))
		}
		if expression := assignment.Expression(); expression != nil {
			collect(query, expression)
		}
	}
	if condition := item.Search_condition(); condition != nil {
		collect(query, condition)
	}
	return result
}

func deletion(item *parser.Delete_statementContext) ir.Statement {
	var target *ir.Name
	if from := item.Delete_statement_from(); from != nil {
		target = targetName(from.Ddl_object())
	}
	query := &ir.Query{CTEs: ctes(item.With_expression())}
	if target != nil {
		query.Sources = []ir.Source{{Table: target}}
	}
	if sources := item.From_table_sources(); sources != nil {
		tableSources(sources.Table_sources(), query)
	}
	if condition := item.Search_condition(); condition != nil {
		collect(query, condition)
	}
	return ir.Statement{Kind: ir.KindDelete, Target: target, Query: query}
}

func merge(item *parser.Merge_statementContext) ir.Statement {
	target := targetName(item.Ddl_object())
	query := &ir.Query{CTEs: ctes(item.With_expression())}
	if target != nil {
		query.Sources = []ir.Source{{Alias: aliasOf(item.As_table_alias()), Table: target}}
	}
	if sources := item.Table_sources(); sources != nil {
		tableSources(sources, query)
	}
	collect(query, item.Search_condition())
	result := ir.Statement{Kind: ir.KindMerge, Target: target, Query: query, AllColumns: true}
	for _, clause := range item.AllWhen_matches() {
		collect(query, clause)
	}
	return result
}
