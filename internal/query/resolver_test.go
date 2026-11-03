package query_test

import (
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"dataguard/internal/connector"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/query"
	"dataguard/internal/query/frontend/mysql"
	"dataguard/internal/query/frontend/postgres"
	"dataguard/internal/query/frontend/tsql"
	"dataguard/internal/query/ir"
)

func columns(names ...string) []connector.Column {
	result := make([]connector.Column, 0, len(names))
	for _, name := range names {
		result = append(result, connector.Column{Name: name})
	}
	return result
}

func table(schema, name string, names ...string) connector.Table {
	return connector.Table{Database: "crm", Schema: schema, Name: name, Kind: agentv1.TableKind_TABLE_KIND_TABLE, Columns: columns(names...)}
}

func view(schema, name, definition string, names ...string) connector.Table {
	item := table(schema, name, names...)
	item.Kind, item.Definition = agentv1.TableKind_TABLE_KIND_VIEW, definition
	return item
}

type dialect struct {
	name           string
	frontend       ir.Frontend
	schema         string
	foldCase       bool
	viewDefinition string
}

func dialects() []dialect {
	return []dialect{
		{"postgres", postgres.Frontend{}, "public", false, "SELECT u.id, u.email AS contact FROM users u WHERE u.status = 'active'"},
		{"mysql", mysql.Frontend{}, "crm", true, "SELECT u.id, u.email AS contact FROM users u WHERE u.status = 'active'"},
		{"tsql", tsql.Frontend{}, "dbo", true, "CREATE VIEW active_users AS SELECT u.id, u.email AS contact FROM users u WHERE u.status = 'active'"},
	}
}

func catalogFor(d dialect) *query.Catalog {
	return query.NewCatalog(d.frontend, []connector.Table{
		table(d.schema, "users", "id", "email", "inn", "status"),
		table(d.schema, "orders", "id", "user_id", "total"),
		view(d.schema, "active_users", d.viewDefinition, "id", "contact"),
	}, d.schema, d.foldCase)
}

func reads(analysis query.Analysis) []string {
	var names []string
	for column, access := range analysis.Columns {
		if access.Read {
			names = append(names, column.Table+"."+column.Name)
		}
	}
	sort.Strings(names)
	return names
}

func writes(analysis query.Analysis) []string {
	var names []string
	for column, access := range analysis.Columns {
		if access.Written {
			names = append(names, column.Table+"."+column.Name)
		}
	}
	sort.Strings(names)
	return names
}

func tables(analysis query.Analysis) []string {
	var names []string
	for _, item := range analysis.Tables {
		names = append(names, item.Name)
	}
	sort.Strings(names)
	return names
}

type corpusCase struct {
	name      string
	sql       string
	operation agentv1.OperationType
	reads     []string
	writes    []string
	tables    []string
}

const (
	opSelect = agentv1.OperationType_OPERATION_TYPE_SELECT
	opInsert = agentv1.OperationType_OPERATION_TYPE_INSERT
	opUpdate = agentv1.OperationType_OPERATION_TYPE_UPDATE
	opDelete = agentv1.OperationType_OPERATION_TYPE_DELETE
)

// corpus holds queries valid in all three dialects, so the shared resolver is
// proven against every frontend with the same expectations.
func corpus() []corpusCase {
	return []corpusCase{
		{"simple select", "SELECT email, inn FROM users WHERE id = 123", opSelect,
			[]string{"users.email", "users.id", "users.inn"}, nil, []string{"users"}},
		{"star", "SELECT * FROM orders", opSelect,
			[]string{"orders.id", "orders.total", "orders.user_id"}, nil, []string{"orders"}},
		{"qualified star", "SELECT o.* FROM orders o JOIN users u ON u.id = o.user_id", opSelect,
			[]string{"orders.id", "orders.total", "orders.user_id", "users.id"}, nil, []string{"orders", "users"}},
		{"alias and join", "SELECT u.email, o.total FROM users u JOIN orders o ON o.user_id = u.id", opSelect,
			[]string{"orders.total", "orders.user_id", "users.email", "users.id"}, nil, []string{"orders", "users"}},
		{"filter counts as access", "SELECT id FROM users WHERE inn = '500100732259'", opSelect,
			[]string{"users.id", "users.inn"}, nil, []string{"users"}},
		{"function argument", "SELECT UPPER(email) FROM users", opSelect,
			[]string{"users.email"}, nil, []string{"users"}},
		{"count star reads no column", "SELECT COUNT(*) FROM users", opSelect, nil, nil, []string{"users"}},
		{"subquery in where", "SELECT id FROM orders WHERE user_id IN (SELECT id FROM users WHERE status = 'x')", opSelect,
			[]string{"orders.id", "orders.user_id", "users.id", "users.status"}, nil, []string{"orders", "users"}},
		{"correlated subquery", "SELECT o.id FROM orders o WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = o.user_id)", opSelect,
			[]string{"orders.id", "orders.user_id", "users.id"}, nil, []string{"orders", "users"}},
		{"derived table", "SELECT d.email FROM (SELECT id, email FROM users) d", opSelect,
			[]string{"users.email"}, nil, []string{"users"}},
		{"derived alias", "SELECT d.c FROM (SELECT email AS c FROM users) d", opSelect,
			[]string{"users.email"}, nil, []string{"users"}},
		{"cte", "WITH c AS (SELECT email FROM users) SELECT email FROM c", opSelect,
			[]string{"users.email"}, nil, []string{"users"}},
		{"union", "SELECT email FROM users UNION SELECT inn FROM users", opSelect,
			[]string{"users.email", "users.inn"}, nil, []string{"users"}},
		{"view exposes base column", "SELECT contact FROM active_users", opSelect,
			[]string{"users.email", "users.status"}, nil, []string{"active_users", "users"}},
		{"view star", "SELECT * FROM active_users", opSelect,
			[]string{"users.email", "users.id", "users.status"}, nil, []string{"active_users", "users"}},
		{"view omits unused column", "SELECT id FROM active_users", opSelect,
			[]string{"users.id", "users.status"}, nil, []string{"active_users", "users"}},
		{"insert values", "INSERT INTO orders (id, total) VALUES (1, 2)", opInsert,
			nil, []string{"orders.id", "orders.total"}, []string{"orders"}},
		{"insert select", "INSERT INTO orders (id, total) SELECT id, id FROM users", opInsert,
			[]string{"users.id"}, []string{"orders.id", "orders.total"}, []string{"orders", "users"}},
		{"update", "UPDATE users SET email = 'x' WHERE id = 1", opUpdate,
			[]string{"users.id"}, []string{"users.email"}, []string{"users"}},
		{"delete", "DELETE FROM users WHERE inn = '1'", opDelete,
			[]string{"users.inn"}, nil, []string{"users"}},
	}
}

func TestResolverCorpus(t *testing.T) {
	for _, d := range dialects() {
		catalog := catalogFor(d)
		for _, testCase := range corpus() {
			t.Run(d.name+"/"+testCase.name, func(t *testing.T) {
				analysis := catalog.Analyze(testCase.sql)
				if analysis.Resolution != agentv1.ObjectResolution_OBJECT_RESOLUTION_RESOLVED {
					t.Errorf("resolution = %s, reads %v", analysis.Resolution, reads(analysis))
				}
				if analysis.Operation != testCase.operation {
					t.Errorf("operation = %s", analysis.Operation)
				}
				if got := reads(analysis); !reflect.DeepEqual(got, testCase.reads) {
					t.Errorf("reads = %v, want %v", got, testCase.reads)
				}
				if got := writes(analysis); !reflect.DeepEqual(got, testCase.writes) {
					t.Errorf("writes = %v, want %v", got, testCase.writes)
				}
				if got := tables(analysis); !reflect.DeepEqual(got, testCase.tables) {
					t.Errorf("tables = %v, want %v", got, testCase.tables)
				}
			})
		}
	}
}

func TestPartialAndUnresolved(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want agentv1.ObjectResolution
	}{
		{"unknown table", "SELECT a FROM not_in_catalog", agentv1.ObjectResolution_OBJECT_RESOLUTION_UNRESOLVED},
		{"known and unknown", "SELECT u.email FROM users u JOIN not_in_catalog n ON n.id = u.id", agentv1.ObjectResolution_OBJECT_RESOLUTION_PARTIAL},
		{"unknown column", "SELECT no_such_column FROM users", agentv1.ObjectResolution_OBJECT_RESOLUTION_PARTIAL},
		{"garbage", "THIS IS NOT SQL @@@", agentv1.ObjectResolution_OBJECT_RESOLUTION_UNRESOLVED},
	}
	for _, d := range dialects() {
		catalog := catalogFor(d)
		for _, testCase := range cases {
			t.Run(d.name+"/"+testCase.name, func(t *testing.T) {
				if got := catalog.Analyze(testCase.sql); got.Resolution != testCase.want {
					t.Fatalf("resolution = %s, want %s", got.Resolution, testCase.want)
				}
			})
		}
	}
}

func TestFingerprintIgnoresLiteralsButNotStructure(t *testing.T) {
	for _, d := range dialects() {
		t.Run(d.name, func(t *testing.T) {
			catalog := catalogFor(d)
			first := catalog.Analyze("SELECT email FROM users WHERE inn = '500100732259'")
			second := catalog.Analyze("SELECT email FROM users WHERE inn = '770708389312'")
			other := catalog.Analyze("SELECT inn FROM users WHERE inn = '500100732259'")
			if first.Fingerprint == "" || first.Fingerprint != second.Fingerprint {
				t.Fatalf("literals changed the fingerprint: %s / %s", first.Fingerprint, second.Fingerprint)
			}
			if first.Fingerprint == other.Fingerprint {
				t.Fatal("different columns must differ")
			}
		})
	}
}

func TestUnparsableTextHasNoFingerprintAndNoObjects(t *testing.T) {
	for _, d := range dialects() {
		analysis := catalogFor(d).Analyze("SELEC email FRM users WHERE inn = 'dgcanary'")
		if analysis.Fingerprint != "" || len(analysis.Tables) != 0 || len(analysis.Columns) != 0 {
			t.Fatalf("%s: analysis kept something: %+v", d.name, analysis)
		}
	}
}

// TestLiteralsNeverAppearInAnalysis guards against a parser treating a value as
// an identifier: only catalog names can come out.
func TestLiteralsNeverAppearInAnalysis(t *testing.T) {
	for _, d := range dialects() {
		catalog := catalogFor(d)
		analysis := catalog.Analyze("SELECT 'dgcanary' AS dgcanary_alias, email FROM users WHERE inn = 'dgcanary'")
		for column := range analysis.Columns {
			if strings.Contains(column.Name, "dgcanary") {
				t.Fatalf("%s: value reached the analysis: %+v", d.name, column)
			}
		}
	}
}

func TestPostgresSpecifics(t *testing.T) {
	catalog := query.NewCatalog(postgres.Frontend{}, []connector.Table{
		table("public", "users", "id", "email"),
		table("audit", "users", "id", "actor"),
		view("public", "v_loop", "SELECT id FROM v_loop", "id"),
	}, "public", false)

	t.Run("schema qualified", func(t *testing.T) {
		analysis := catalog.Analyze("SELECT actor FROM audit.users")
		if got := reads(analysis); !reflect.DeepEqual(got, []string{"users.actor"}) {
			t.Fatalf("reads = %v", got)
		}
	})
	t.Run("whole row reference", func(t *testing.T) {
		analysis := catalog.Analyze("SELECT row_to_json(u) FROM users u")
		if got := reads(analysis); !reflect.DeepEqual(got, []string{"users.email", "users.id"}) {
			t.Fatalf("reads = %v", got)
		}
	})
	t.Run("order by alias", func(t *testing.T) {
		analysis := catalog.Analyze("SELECT email AS e FROM users ORDER BY e")
		if analysis.Resolution != agentv1.ObjectResolution_OBJECT_RESOLUTION_RESOLVED {
			t.Fatalf("resolution = %s", analysis.Resolution)
		}
	})
	t.Run("using clause", func(t *testing.T) {
		analysis := catalog.Analyze("SELECT email FROM users JOIN audit.users a USING (id)")
		if analysis.Resolution != agentv1.ObjectResolution_OBJECT_RESOLUTION_RESOLVED {
			t.Fatalf("resolution = %s", analysis.Resolution)
		}
	})
	t.Run("recursive cte", func(t *testing.T) {
		analysis := catalog.Analyze(`WITH RECURSIVE r AS (SELECT id FROM users UNION ALL SELECT u.id FROM users u JOIN r ON r.id = u.id) SELECT id FROM r`)
		if analysis.Resolution != agentv1.ObjectResolution_OBJECT_RESOLUTION_RESOLVED || !slices.Contains(reads(analysis), "users.id") {
			t.Fatalf("analysis = %+v", analysis)
		}
	})
	t.Run("dynamic statements are unresolved", func(t *testing.T) {
		for _, sql := range []string{"CALL export_everything()", "DO $$ BEGIN PERFORM 1; END $$"} {
			if got := catalog.Analyze(sql).Resolution; got != agentv1.ObjectResolution_OBJECT_RESOLUTION_UNRESOLVED {
				t.Fatalf("%s: resolution = %s", sql, got)
			}
		}
	})
	t.Run("view cycle terminates", func(t *testing.T) {
		analysis := catalog.Analyze("SELECT id FROM v_loop")
		if analysis.Resolution == agentv1.ObjectResolution_OBJECT_RESOLUTION_RESOLVED {
			t.Fatal("a view cycle cannot be fully resolved")
		}
	})
	t.Run("parameters are not literals", func(t *testing.T) {
		analysis := catalog.Analyze("SELECT email FROM users WHERE id = $1")
		if got := reads(analysis); !reflect.DeepEqual(got, []string{"users.email", "users.id"}) {
			t.Fatalf("reads = %v", got)
		}
	})
}

func BenchmarkAnalyze(b *testing.B) {
	for _, d := range dialects() {
		catalog := catalogFor(d)
		b.Run(d.name, func(b *testing.B) {
			for b.Loop() {
				catalog.Analyze("SELECT u.email, o.total FROM users u JOIN orders o ON o.user_id = u.id WHERE u.inn = '1'")
			}
		})
	}
}
