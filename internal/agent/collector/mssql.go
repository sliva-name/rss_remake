package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
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
	if position.File != "" && len(rows) > 0 && !slices.ContainsFunc(rows, func(row connector.AuditRow) bool { return row.File == position.File }) {
		batch.Gap = lostLogGap()
	}
	// fn_get_audit_file restarts at the beginning of the offset, so ordinals are
	// counted from zero again; the first position.Seen of them were delivered.
	next := position.start()
	var merged *Record
	for i := range rows {
		row := &rows[i]
		next = next.step(row)
		if next.within(position) {
			continue
		}
		merged = mergeRow(&batch, merged, row, next)
	}
	if merged != nil {
		batch.Records = append(batch.Records, *merged)
	}
	if next.within(position) {
		next = position
	}
	batch.Cursor, err = r.moveTo(next)
	if err != nil {
		return Batch{}, err
	}
	return batch, nil
}

// start is the cursor before the first record of the current offset.
func (c mssqlCursor) start() mssqlCursor {
	return mssqlCursor{File: c.File, Offset: c.Offset}
}

// step moves the cursor onto row. Records sharing an offset are told apart by
// their ordinal in it.
func (c mssqlCursor) step(row *connector.AuditRow) mssqlCursor {
	if row.File == c.File && row.Offset == c.Offset {
		c.Seen++
		return c
	}
	return mssqlCursor{File: row.File, Offset: row.Offset, Seen: 1}
}

// within reports whether position already covers the cursor.
func (c mssqlCursor) within(position mssqlCursor) bool {
	return c.File == position.File && c.Offset == position.Offset && c.Seen <= position.Seen
}

// moveTo makes position the live cursor and encodes it for the batch.
func (r *sqlServerReader) moveTo(position mssqlCursor) ([]byte, error) {
	r.live = &position
	cursor, err := json.Marshal(position)
	if err != nil {
		return nil, fmt.Errorf("encode audit cursor: %w", err)
	}
	return cursor, nil
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
	cursor, err := r.moveTo(position)
	if err != nil {
		return Batch{}, err
	}
	return Batch{Cursor: cursor}, nil
}

// advance moves past rows, and stays at position when they bring nothing new.
func advance(position mssqlCursor, rows []connector.AuditRow) mssqlCursor {
	next := position.start()
	for i := range rows {
		next = next.step(&rows[i])
	}
	if next.within(position) {
		return position
	}
	return next
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
