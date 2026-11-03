package asset_test

import (
	"testing"

	"github.com/google/uuid"

	"dataguard/internal/core/asset"
)

func column(name, nativeType string, ordinal int32) asset.Column {
	return asset.Column{ID: uuid.New(), Name: name, NativeType: nativeType, Ordinal: ordinal, Status: asset.StatusActive}
}

func stored(name string, columns ...asset.Column) asset.Table {
	return asset.Table{
		ID: uuid.New(), Database: "crm", Schema: "public", Name: name, Status: asset.StatusActive,
		Columns: columns, Fingerprint: asset.Fingerprint(columns),
	}
}

func incoming(name string, columns ...asset.Column) asset.Table {
	for i := range columns {
		columns[i].ID = uuid.Nil
	}
	return asset.Table{Database: "crm", Schema: "public", Name: name, Columns: columns}
}

func kinds(plan asset.Plan) map[string]int {
	counts := map[string]int{}
	for _, change := range plan.Changes {
		counts[change.Kind]++
	}
	return counts
}

func find(plan asset.Plan, name string) asset.Table {
	for _, table := range plan.Tables {
		if table.Name == name {
			return table
		}
	}
	return asset.Table{}
}

func TestUnchangedTableKeepsIdsAndProducesNoChanges(t *testing.T) {
	email := column("email", "text", 1)
	current := stored("users", email)

	plan := asset.Reconcile([]asset.Table{current}, []asset.Table{incoming("users", email)})

	if len(plan.Changes) != 0 || len(plan.Renames) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
	if got := find(plan, "users"); got.ID != current.ID || got.Columns[0].ID != current.Columns[0].ID {
		t.Fatalf("ids changed: %+v", got)
	}
}

func TestNewTableAndColumns(t *testing.T) {
	plan := asset.Reconcile(nil, []asset.Table{incoming("users", column("email", "text", 1))})

	if kinds(plan)[asset.ChangeTableAdded] != 1 {
		t.Fatalf("changes = %v", kinds(plan))
	}
	created := find(plan, "users")
	if created.ID == uuid.Nil || created.Columns[0].ID == uuid.Nil {
		t.Fatalf("ids not assigned: %+v", created)
	}
}

func TestTableRenameKeepsIdentity(t *testing.T) {
	current := stored("users", column("email", "text", 1))
	plan := asset.Reconcile([]asset.Table{current}, []asset.Table{incoming("customers", column("email", "text", 1))})

	renamed := find(plan, "customers")
	if renamed.ID != current.ID || renamed.Columns[0].ID != current.Columns[0].ID {
		t.Fatalf("identity lost: %+v", renamed)
	}
	if len(plan.Renames) != 1 || plan.Renames[0].OldName != "users" {
		t.Fatalf("renames = %+v", plan.Renames)
	}
	if kinds(plan)[asset.ChangeTableRemoved] != 0 {
		t.Fatal("a rename must not count as a removal")
	}
}

func TestAmbiguousRenameIsNotGuessed(t *testing.T) {
	first := stored("a", column("email", "text", 1))
	second := stored("b", column("email", "text", 1))

	plan := asset.Reconcile([]asset.Table{first, second}, []asset.Table{incoming("c", column("email", "text", 1))})

	if len(plan.Renames) != 0 {
		t.Fatalf("guessed a rename: %+v", plan.Renames)
	}
	counts := kinds(plan)
	if counts[asset.ChangeTableAdded] != 1 || counts[asset.ChangeTableRemoved] != 2 {
		t.Fatalf("changes = %v", counts)
	}
}

func TestColumnRenameByTypeAndPosition(t *testing.T) {
	current := stored("users", column("id", "bigint", 1), column("email", "text", 2))
	plan := asset.Reconcile([]asset.Table{current}, []asset.Table{
		incoming("users", column("id", "bigint", 1), column("email_address", "text", 2)),
	})

	if len(plan.Renames) != 1 || plan.Renames[0].ObjectID != current.Columns[1].ID || plan.Renames[0].NewName != "email_address" {
		t.Fatalf("renames = %+v", plan.Renames)
	}
	if counts := kinds(plan); counts[asset.ChangeColumnRemoved] != 0 || counts[asset.ChangeColumnAdded] != 0 {
		t.Fatalf("changes = %v", counts)
	}
}

func TestColumnWithOtherTypeIsNotARename(t *testing.T) {
	current := stored("users", column("code", "text", 1))
	plan := asset.Reconcile([]asset.Table{current}, []asset.Table{incoming("users", column("amount", "bigint", 1))})

	counts := kinds(plan)
	if len(plan.Renames) != 0 || counts[asset.ChangeColumnAdded] != 1 || counts[asset.ChangeColumnRemoved] != 1 {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestRemovedColumnStaysInHistory(t *testing.T) {
	current := stored("users", column("id", "bigint", 1), column("email", "text", 2))
	plan := asset.Reconcile([]asset.Table{current}, []asset.Table{incoming("users", column("id", "bigint", 1))})

	table := find(plan, "users")
	if len(table.Columns) != 2 {
		t.Fatalf("columns = %+v", table.Columns)
	}
	if table.Columns[1].Status != asset.StatusRemoved || table.Columns[1].ID != current.Columns[1].ID {
		t.Fatalf("column = %+v", table.Columns[1])
	}
}

func TestRemovedTableReappearsWithItsIdentity(t *testing.T) {
	current := stored("users", column("email", "text", 1))
	current.Status = asset.StatusRemoved

	plan := asset.Reconcile([]asset.Table{current}, []asset.Table{incoming("users", column("email", "text", 1))})

	back := find(plan, "users")
	if back.ID != current.ID || back.Status != asset.StatusActive {
		t.Fatalf("table = %+v", back)
	}
}

func TestSchemaDriftIsReported(t *testing.T) {
	current := stored("users", column("email", "text", 1))
	plan := asset.Reconcile([]asset.Table{current}, []asset.Table{
		incoming("users", column("email", "text", 1), column("phone", "text", 2)),
	})
	if kinds(plan)[asset.ChangeSchemaDrift] != 1 {
		t.Fatalf("changes = %v", kinds(plan))
	}
}

func TestFingerprintIgnoresColumnOrderOfCatalog(t *testing.T) {
	a := asset.Fingerprint([]asset.Column{column("a", "text", 1), column("b", "int", 2)})
	b := asset.Fingerprint([]asset.Column{column("b", "int", 2), column("a", "text", 1)})
	if a != b {
		t.Fatal("fingerprint must not depend on listing order")
	}
}
