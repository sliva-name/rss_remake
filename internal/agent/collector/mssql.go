package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"dataguard/internal/connector"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

// sqlServerReader reads SQL Server Audit through SQL. Records in one audit buffer
// share file and offset, so a position needs the ordinal inside that offset.
type sqlServerReader struct {
	source  connector.AuditLogSource
	pattern string
	live    *mssqlCursor
	loaded  bool
}

type mssqlCursor struct {
	File   string `json:"file"`
	Offset int64  `json:"offset"`
	// Seen counts records of this offset already delivered.
	Seen int `json:"seen"`
}

// mssqlFreshStart marks the first read ever: it only finds the end of the existing
// log, because history before installation is not audited.
const mssqlFreshStart = ""

func (r *sqlServerReader) resume(cursor []byte) error {
	if r.loaded {
		return nil
	}
	r.loaded = true
	if cursor == nil {
		return nil
	}
	r.live = &mssqlCursor{}
	if err := json.Unmarshal(cursor, r.live); err != nil {
		return fmt.Errorf("decode audit cursor: %w", err)
	}
	return nil
}

// Rewind implements Reader.
func (r *sqlServerReader) Rewind() {
	r.loaded = false
	r.live = nil
}

// Read implements Reader.
func (r *sqlServerReader) Read(ctx context.Context, cursor []byte) (Batch, error) {
	if err := r.resume(cursor); err != nil {
		return Batch{}, err
	}
	if r.live == nil {
		return r.seekEnd(ctx)
	}
	position := *r.live
	rows, err := r.source.AuditRows(ctx, r.pattern, position.File, position.Offset)
	if err != nil {
		return r.recover(ctx, err)
	}
	var batch Batch
	if position.File != "" && !containsFile(rows, position.File) && len(rows) > 0 {
		batch.Gap = lostLogGap()
	}
	// fn_get_audit_file restarts at the beginning of the offset, so ordinals are
	// counted from zero again; the first position.Seen of them were delivered.
	next := mssqlCursor{File: position.File, Offset: position.Offset}
	var merged *Record
	for i := range rows {
		row := &rows[i]
		if row.File == next.File && row.Offset == next.Offset {
			next.Seen++
		} else {
			next = mssqlCursor{File: row.File, Offset: row.Offset, Seen: 1}
		}
		if row.File == position.File && row.Offset == position.Offset && next.Seen <= position.Seen {
			continue
		}
		merged = mergeRow(&batch, merged, row, next)
	}
	if merged != nil {
		batch.Records = append(batch.Records, *merged)
	}
	if next.File == position.File && next.Offset == position.Offset && next.Seen < position.Seen {
		next = position
	}
	r.live = &next
	batch.Cursor, err = json.Marshal(next)
	if err != nil {
		return Batch{}, fmt.Errorf("encode audit cursor: %w", err)
	}
	return batch, nil
}

// recover handles a cursor whose file was removed by rollover. The server refuses
// to start from a file that no longer exists, so without this the reader would
// fail forever. If the log is readable from its start, the cursor is lost: what
// was not read is reported as a gap and reading resumes at the end.
func (r *sqlServerReader) recover(ctx context.Context, cause error) (Batch, error) {
	if _, err := r.source.AuditRows(ctx, r.pattern, "", 0); err != nil {
		return Batch{}, cause
	}
	batch, err := r.seekEnd(ctx)
	if err != nil {
		return Batch{}, err
	}
	batch.Gap = lostLogGap()
	return batch, nil
}

// seekEnd skips the history that exists before the first start. Reads are paged,
// so it pages until a read brings nothing new; stopping after one page would
// replay old history as if it had just happened.
func (r *sqlServerReader) seekEnd(ctx context.Context) (Batch, error) {
	position := mssqlCursor{File: mssqlFreshStart}
	for {
		rows, err := r.source.AuditRows(ctx, r.pattern, position.File, position.Offset)
		if err != nil {
			return Batch{}, err
		}
		next := advance(position, rows)
		if next == position {
			break
		}
		position = next
	}
	r.live = &position
	cursor, err := json.Marshal(position)
	if err != nil {
		return Batch{}, fmt.Errorf("encode audit cursor: %w", err)
	}
	return Batch{Cursor: cursor}, nil
}

// advance moves past rows; records sharing an offset are counted by ordinal.
func advance(position mssqlCursor, rows []connector.AuditRow) mssqlCursor {
	next := mssqlCursor{File: position.File, Offset: position.Offset}
	for i := range rows {
		row := &rows[i]
		if row.File == next.File && row.Offset == next.Offset {
			next.Seen++
		} else {
			next = mssqlCursor{File: row.File, Offset: row.Offset, Seen: 1}
		}
	}
	if next.File == position.File && next.Offset == position.Offset && next.Seen <= position.Seen {
		return position
	}
	return next
}

func containsFile(rows []connector.AuditRow, file string) bool {
	for i := range rows {
		if rows[i].File == file {
			return true
		}
	}
	return false
}

// mergeRow folds the rows of one statement. SQL Server writes one row per table,
// which would otherwise count a join as several accesses, and splits long text
// into numbered parts.
func mergeRow(batch *Batch, current *Record, row *connector.AuditRow, position mssqlCursor) *Record {
	if !row.UserObject {
		return current
	}
	if current != nil && sameStatement(current, row) {
		if row.Sequence > 1 {
			current.Statement = NewStatement(current.Statement.Reveal() + row.Statement)
		}
		return current
	}
	if current != nil {
		batch.Records = append(batch.Records, *current)
	}
	status := agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS
	if !row.Succeeded {
		status = agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE
	}
	return &Record{
		Position:      row.File + ":" + strconv.FormatInt(position.Offset, 10) + ":" + strconv.Itoa(position.Seen),
		Time:          row.Time.UTC().Truncate(time.Microsecond),
		Statement:     NewStatement(row.Statement),
		Principal:     row.Principal,
		ClientAddress: row.ClientAddress,
		Session:       strconv.Itoa(row.Session),
		Transaction:   strconv.FormatInt(row.Transaction, 10),
		Status:        status,
	}
}

// sameStatement also compares the time: rows written for the tables of one
// statement share it, while running the same text twice gives two times.
func sameStatement(current *Record, row *connector.AuditRow) bool {
	return current.Session == strconv.Itoa(row.Session) &&
		current.Transaction == strconv.FormatInt(row.Transaction, 10) &&
		current.Time.Equal(row.Time.UTC().Truncate(time.Microsecond)) &&
		(row.Sequence > 1 || current.Statement.Reveal() == row.Statement)
}
