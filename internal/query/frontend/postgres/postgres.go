// Package postgres parses PostgreSQL with the server's own grammar, compiled to
// WebAssembly so the agent stays a static binary without cgo.
package postgres

import (
	"errors"

	pganalyze "github.com/pganalyze/pg_query_go/v6"
	pgquery "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"dataguard/internal/query/ir"
)

// Frontend implements ir.Frontend.
type Frontend struct{}

var errNotParsed = errors.New("statement could not be parsed")

// Parse drops the parser's error, which quotes the query.
func (Frontend) Parse(text string) ([]ir.Statement, error) {
	tree, err := pgquery.Parse(text)
	if err != nil {
		return nil, errNotParsed
	}
	statements := make([]ir.Statement, 0, len(tree.GetStmts()))
	for _, raw := range tree.GetStmts() {
		statements = append(statements, convert(raw.GetStmt()))
	}
	return statements, nil
}

func convert(node *pganalyze.Node) ir.Statement {
	switch item := node.GetNode().(type) {
	case *pganalyze.Node_SelectStmt:
		return ir.Statement{Kind: ir.KindSelect, Query: selectQuery(item.SelectStmt)}
	case *pganalyze.Node_InsertStmt:
		return insert(item.InsertStmt)
	case *pganalyze.Node_UpdateStmt:
		return update(item.UpdateStmt)
	case *pganalyze.Node_DeleteStmt:
		return deletion(item.DeleteStmt)
	case *pganalyze.Node_MergeStmt:
		return merge(item.MergeStmt)
	case *pganalyze.Node_CallStmt, *pganalyze.Node_DoStmt, *pganalyze.Node_ExecuteStmt:
		return ir.Statement{Kind: ir.KindOther, Dynamic: true}
	case *pganalyze.Node_GrantStmt, *pganalyze.Node_GrantRoleStmt, *pganalyze.Node_CreateRoleStmt,
		*pganalyze.Node_AlterRoleStmt, *pganalyze.Node_DropRoleStmt:
		return ir.Statement{Kind: ir.KindDCL}
	case *pganalyze.Node_CreateStmt, *pganalyze.Node_AlterTableStmt, *pganalyze.Node_DropStmt,
		*pganalyze.Node_RenameStmt, *pganalyze.Node_IndexStmt, *pganalyze.Node_ViewStmt, *pganalyze.Node_TruncateStmt:
		return ir.Statement{Kind: ir.KindDDL}
	default:
		return ir.Statement{Kind: ir.KindOther}
	}
}

func selectQuery(statement *pganalyze.SelectStmt) *ir.Query {
	if statement.GetOp() != pganalyze.SetOperation_SETOP_NONE {
		query := selectQuery(statement.GetLarg())
		query.Arms = append(query.Arms, selectQuery(statement.GetRarg()))
		query.CTEs = append(cteList(statement.GetWithClause()), query.CTEs...)
		return query
	}
	query := &ir.Query{CTEs: cteList(statement.GetWithClause())}
	for _, item := range statement.GetFromClause() {
		fromItem(item, query)
	}
	for _, target := range statement.GetTargetList() {
		query.Projections = append(query.Projections, projection(target.GetResTarget(), query))
	}
	collect(query, statement.GetWhereClause())
	collectAll(query, statement.GetGroupClause())
	collect(query, statement.GetHavingClause())
	collectAll(query, statement.GetSortClause())
	collectAll(query, statement.GetWindowClause())
	return query
}

func cteList(clause *pganalyze.WithClause) []ir.CTE {
	var ctes []ir.CTE
	for _, node := range clause.GetCtes() {
		cte := node.GetCommonTableExpr()
		if cte == nil {
			continue
		}
		item := ir.CTE{Name: cte.GetCtename(), Query: &ir.Query{}}
		for _, alias := range cte.GetAliascolnames() {
			item.Columns = append(item.Columns, alias.GetString_().GetSval())
		}
		if inner := cte.GetCtequery().GetSelectStmt(); inner != nil {
			item.Query = selectQuery(inner)
		}
		ctes = append(ctes, item)
	}
	return ctes
}

func fromItem(node *pganalyze.Node, query *ir.Query) {
	switch item := node.GetNode().(type) {
	case *pganalyze.Node_RangeVar:
		query.Sources = append(query.Sources, rangeVar(item.RangeVar))
	case *pganalyze.Node_RangeSubselect:
		source := ir.Source{Alias: item.RangeSubselect.GetAlias().GetAliasname()}
		for _, name := range item.RangeSubselect.GetAlias().GetColnames() {
			source.Columns = append(source.Columns, name.GetString_().GetSval())
		}
		if inner := item.RangeSubselect.GetSubquery().GetSelectStmt(); inner != nil {
			source.Query = selectQuery(inner)
		}
		query.Sources = append(query.Sources, source)
	case *pganalyze.Node_JoinExpr:
		fromItem(item.JoinExpr.GetLarg(), query)
		fromItem(item.JoinExpr.GetRarg(), query)
		collect(query, item.JoinExpr.GetQuals())
		for _, name := range item.JoinExpr.GetUsingClause() {
			query.Refs = append(query.Refs, ir.ColumnRef{Name: name.GetString_().GetSval()})
		}
	case *pganalyze.Node_RangeFunction:
		query.Calls = true
		query.Sources = append(query.Sources, ir.Source{Opaque: true})
	default:
		query.Sources = append(query.Sources, ir.Source{Opaque: true})
	}
}

func rangeVar(table *pganalyze.RangeVar) ir.Source {
	return ir.Source{
		Alias: table.GetAlias().GetAliasname(),
		Table: &ir.Name{Catalog: table.GetCatalogname(), Schema: table.GetSchemaname(), Table: table.GetRelname()},
	}
}

func projection(target *pganalyze.ResTarget, query *ir.Query) ir.Projection {
	item := ir.Projection{Alias: target.GetName()}
	if reference := target.GetVal().GetColumnRef(); reference != nil {
		if qualifier, isStar := starOf(reference); isStar {
			item.Star, item.StarQualifier = true, qualifier
			return item
		}
	}
	scratch := &ir.Query{}
	collect(scratch, target.GetVal())
	item.Refs = scratch.Refs
	query.Subqueries = append(query.Subqueries, scratch.Subqueries...)
	query.Calls = query.Calls || scratch.Calls
	return item
}

func starOf(reference *pganalyze.ColumnRef) (string, bool) {
	fields := reference.GetFields()
	if len(fields) == 0 || fields[len(fields)-1].GetAStar() == nil {
		return "", false
	}
	if len(fields) == 1 {
		return "", true
	}
	return fields[len(fields)-2].GetString_().GetSval(), true
}

func columnRef(reference *pganalyze.ColumnRef) (ir.ColumnRef, bool) {
	fields := reference.GetFields()
	if len(fields) == 0 {
		return ir.ColumnRef{}, false
	}
	name := fields[len(fields)-1].GetString_()
	if name == nil {
		return ir.ColumnRef{}, false
	}
	result := ir.ColumnRef{Name: name.GetSval()}
	if len(fields) > 1 {
		result.Qualifier = fields[len(fields)-2].GetString_().GetSval()
	}
	return result, true
}

func collectAll(query *ir.Query, nodes []*pganalyze.Node) {
	for _, node := range nodes {
		collect(query, node)
	}
}

// collect walks any expression by reflection. PostgreSQL has hundreds of node
// types; only column references and subqueries matter, and a generic walk cannot
// miss one inside an expression it has never heard of.
func collect(query *ir.Query, message proto.Message) {
	if message == nil {
		return
	}
	value := message.ProtoReflect()
	if !value.IsValid() {
		return
	}
	switch node := message.(type) {
	case *pganalyze.ColumnRef:
		if reference, ok := columnRef(node); ok {
			query.Refs = append(query.Refs, reference)
		}
		return
	case *pganalyze.SelectStmt:
		query.Subqueries = append(query.Subqueries, selectQuery(node))
		return
	case *pganalyze.FuncCall:
		query.Calls = true
	}
	value.Range(func(field protoreflect.FieldDescriptor, item protoreflect.Value) bool {
		collectField(query, field, item)
		return true
	})
}

func collectField(query *ir.Query, field protoreflect.FieldDescriptor, item protoreflect.Value) {
	if field.Kind() != protoreflect.MessageKind {
		return
	}
	if !field.IsList() {
		collect(query, item.Message().Interface())
		return
	}
	list := item.List()
	for i := range list.Len() {
		collect(query, list.Get(i).Message().Interface())
	}
}

func insert(statement *pganalyze.InsertStmt) ir.Statement {
	result := ir.Statement{Kind: ir.KindInsert}
	target := rangeVar(statement.GetRelation())
	result.Target = target.Table
	for _, column := range statement.GetCols() {
		result.Written = append(result.Written, column.GetResTarget().GetName())
	}
	result.AllColumns = len(result.Written) == 0
	if inner := statement.GetSelectStmt().GetSelectStmt(); inner != nil {
		result.Query = selectQuery(inner)
		result.Query.CTEs = append(cteList(statement.GetWithClause()), result.Query.CTEs...)
	}
	return result
}

func update(statement *pganalyze.UpdateStmt) ir.Statement {
	target := rangeVar(statement.GetRelation())
	query := &ir.Query{CTEs: cteList(statement.GetWithClause()), Sources: []ir.Source{target}}
	for _, item := range statement.GetFromClause() {
		fromItem(item, query)
	}
	result := ir.Statement{Kind: ir.KindUpdate, Target: target.Table, Query: query}
	for _, node := range statement.GetTargetList() {
		assignment := node.GetResTarget()
		result.Written = append(result.Written, assignment.GetName())
		collect(query, assignment.GetVal())
	}
	collect(query, statement.GetWhereClause())
	return result
}

func deletion(statement *pganalyze.DeleteStmt) ir.Statement {
	target := rangeVar(statement.GetRelation())
	query := &ir.Query{CTEs: cteList(statement.GetWithClause()), Sources: []ir.Source{target}}
	for _, item := range statement.GetUsingClause() {
		fromItem(item, query)
	}
	collect(query, statement.GetWhereClause())
	return ir.Statement{Kind: ir.KindDelete, Target: target.Table, Query: query}
}

func merge(statement *pganalyze.MergeStmt) ir.Statement {
	target := rangeVar(statement.GetRelation())
	query := &ir.Query{CTEs: cteList(statement.GetWithClause()), Sources: []ir.Source{target}}
	fromItem(statement.GetSourceRelation(), query)
	collect(query, statement.GetJoinCondition())
	result := ir.Statement{Kind: ir.KindMerge, Target: target.Table, Query: query}
	for _, node := range statement.GetMergeWhenClauses() {
		clause := node.GetMergeWhenClause()
		collect(query, clause.GetCondition())
		for _, column := range clause.GetTargetList() {
			assignment := column.GetResTarget()
			result.Written = append(result.Written, assignment.GetName())
			collect(query, assignment.GetVal())
		}
		collectAll(query, clause.GetValues())
	}
	return result
}
