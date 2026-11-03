// Package mysql parses MySQL and MariaDB. The grammar is TiDB's, which covers the
// shared dialect; MariaDB-only syntax fails to parse and is reported as
// unresolved rather than guessed.
package mysql

import (
	"errors"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver" // provides the literal node types

	"dataguard/internal/query/ir"
)

// Frontend implements ir.Frontend. A parser instance is not safe for concurrent
// use, so each call creates one.
type Frontend struct{}

var errNotParsed = errors.New("statement could not be parsed")

// Parse drops the parser's error, which quotes the query.
func (Frontend) Parse(text string) ([]ir.Statement, error) {
	nodes, _, err := parser.New().Parse(text, "", "")
	if err != nil {
		return nil, errNotParsed
	}
	statements := make([]ir.Statement, 0, len(nodes))
	for _, node := range nodes {
		statements = append(statements, convert(node))
	}
	return statements, nil
}

func convert(node ast.StmtNode) ir.Statement {
	switch statement := node.(type) {
	case *ast.SelectStmt:
		return ir.Statement{Kind: ir.KindSelect, Query: selectQuery(statement)}
	case *ast.SetOprStmt:
		return ir.Statement{Kind: ir.KindSelect, Query: setQuery(statement)}
	case *ast.InsertStmt:
		return insert(statement)
	case *ast.UpdateStmt:
		return update(statement)
	case *ast.DeleteStmt:
		return deletion(statement)
	case *ast.CallStmt, *ast.ExecuteStmt:
		return ir.Statement{Kind: ir.KindOther, Dynamic: true}
	case *ast.GrantStmt, *ast.RevokeStmt, *ast.CreateUserStmt, *ast.AlterUserStmt, *ast.DropUserStmt:
		return ir.Statement{Kind: ir.KindDCL}
	case ast.DDLNode:
		return ir.Statement{Kind: ir.KindDDL}
	default:
		return ir.Statement{Kind: ir.KindOther}
	}
}

func ctes(clause *ast.WithClause) []ir.CTE {
	if clause == nil {
		return nil
	}
	result := make([]ir.CTE, 0, len(clause.CTEs))
	for _, cte := range clause.CTEs {
		item := ir.CTE{Name: cte.Name.O, Query: resultQuery(cte.Query.Query)}
		for _, column := range cte.ColNameList {
			item.Columns = append(item.Columns, column.O)
		}
		result = append(result, item)
	}
	return result
}

func resultQuery(node ast.ResultSetNode) *ir.Query {
	switch statement := node.(type) {
	case *ast.SelectStmt:
		return selectQuery(statement)
	case *ast.SetOprStmt:
		return setQuery(statement)
	default:
		return &ir.Query{Sources: []ir.Source{{Opaque: true}}}
	}
}

func setQuery(statement *ast.SetOprStmt) *ir.Query {
	query := selectList(statement.SelectList)
	query.CTEs = append(ctes(statement.With), query.CTEs...)
	return query
}

// selectList folds UNION branches. Parentheses nest another list, hence the
// recursion.
func selectList(list *ast.SetOprSelectList) *ir.Query {
	var query *ir.Query
	for _, node := range list.Selects {
		var arm *ir.Query
		switch item := node.(type) {
		case *ast.SelectStmt:
			arm = selectQuery(item)
		case *ast.SetOprSelectList:
			arm = selectList(item)
		default:
			continue
		}
		if query == nil {
			query = arm
			continue
		}
		query.Arms = append(query.Arms, arm)
	}
	if query == nil {
		return &ir.Query{}
	}
	return query
}

func selectQuery(statement *ast.SelectStmt) *ir.Query {
	query := &ir.Query{CTEs: ctes(statement.With)}
	if statement.From != nil {
		fromItem(statement.From.TableRefs, query)
	}
	if statement.Fields != nil {
		for _, field := range statement.Fields.Fields {
			query.Projections = append(query.Projections, projection(field, query))
		}
	}
	collect(query, statement.Where)
	if statement.GroupBy != nil {
		for _, item := range statement.GroupBy.Items {
			collect(query, item.Expr)
		}
	}
	if statement.Having != nil {
		collect(query, statement.Having.Expr)
	}
	if statement.OrderBy != nil {
		for _, item := range statement.OrderBy.Items {
			collect(query, item.Expr)
		}
	}
	return query
}

func fromItem(node ast.ResultSetNode, query *ir.Query) {
	switch item := node.(type) {
	case nil:
	case *ast.Join:
		fromItem(item.Left, query)
		fromItem(item.Right, query)
		if item.On != nil {
			collect(query, item.On.Expr)
		}
		for _, name := range item.Using {
			query.Refs = append(query.Refs, ir.ColumnRef{Name: name.Name.O})
		}
	case *ast.TableSource:
		query.Sources = append(query.Sources, tableSource(item))
	default:
		query.Sources = append(query.Sources, ir.Source{Opaque: true})
	}
}

func tableSource(source *ast.TableSource) ir.Source {
	alias := source.AsName.O
	switch inner := source.Source.(type) {
	case *ast.TableName:
		return ir.Source{Alias: alias, Table: tableName(inner)}
	case *ast.SelectStmt, *ast.SetOprStmt:
		return ir.Source{Alias: alias, Query: resultQuery(inner)}
	default:
		return ir.Source{Alias: alias, Opaque: true}
	}
}

func tableName(name *ast.TableName) *ir.Name {
	return &ir.Name{Schema: name.Schema.O, Table: name.Name.O}
}

func projection(field *ast.SelectField, query *ir.Query) ir.Projection {
	if field.WildCard != nil {
		return ir.Projection{Star: true, StarQualifier: field.WildCard.Table.O}
	}
	scratch := &ir.Query{}
	collect(scratch, field.Expr)
	query.Subqueries = append(query.Subqueries, scratch.Subqueries...)
	query.Calls = query.Calls || scratch.Calls
	return ir.Projection{Alias: field.AsName.O, Refs: scratch.Refs}
}

// visitor gathers references from any expression; subqueries are not entered
// because they open a scope of their own.
type visitor struct {
	query *ir.Query
}

func (v *visitor) Enter(node ast.Node) (ast.Node, bool) {
	switch item := node.(type) {
	case *ast.ColumnNameExpr:
		v.query.Refs = append(v.query.Refs, ir.ColumnRef{Qualifier: item.Name.Table.O, Name: item.Name.Name.O})
		return node, true
	case *ast.SubqueryExpr:
		v.query.Subqueries = append(v.query.Subqueries, resultQuery(item.Query))
		return node, true
	case *ast.FuncCallExpr:
		v.query.Calls = true
		return node, false
	default:
		return node, false
	}
}

func (v *visitor) Leave(node ast.Node) (ast.Node, bool) { return node, true }

func collect(query *ir.Query, expression ast.ExprNode) {
	if expression != nil {
		expression.Accept(&visitor{query: query})
	}
}

func collectAssignments(query *ir.Query, assignments []*ast.Assignment, statement *ir.Statement) {
	for _, assignment := range assignments {
		statement.Written = append(statement.Written, assignment.Column.Name.O)
		collect(query, assignment.Expr)
	}
}

func insert(statement *ast.InsertStmt) ir.Statement {
	result := ir.Statement{Kind: ir.KindInsert, Query: &ir.Query{}}
	if source, ok := statement.Table.TableRefs.Left.(*ast.TableSource); ok {
		if name, ok := source.Source.(*ast.TableName); ok {
			result.Target = tableName(name)
		}
	}
	for _, column := range statement.Columns {
		result.Written = append(result.Written, column.Name.O)
	}
	for _, row := range statement.Lists {
		for _, value := range row {
			collect(result.Query, value)
		}
	}
	collectAssignments(result.Query, statement.OnDuplicate, &result)
	result.AllColumns = len(statement.Columns) == 0
	if statement.Select != nil {
		result.Query = resultQuery(statement.Select)
	}
	return result
}

func update(statement *ast.UpdateStmt) ir.Statement {
	query := &ir.Query{CTEs: ctes(statement.With)}
	fromItem(statement.TableRefs.TableRefs, query)
	result := ir.Statement{Kind: ir.KindUpdate, Query: query}
	if len(query.Sources) > 0 {
		result.Target = query.Sources[0].Table
	}
	collectAssignments(query, statement.List, &result)
	collect(query, statement.Where)
	return result
}

func deletion(statement *ast.DeleteStmt) ir.Statement {
	query := &ir.Query{CTEs: ctes(statement.With)}
	fromItem(statement.TableRefs.TableRefs, query)
	collect(query, statement.Where)
	result := ir.Statement{Kind: ir.KindDelete, Query: query}
	if len(query.Sources) > 0 {
		result.Target = query.Sources[0].Table
	}
	return result
}
