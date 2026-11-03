package collector

import (
	"encoding/csv"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

const (
	pgauditPrefix     = "AUDIT: "
	pgTimeLayout      = "2006-01-02 15:04:05.000 MST"
	clientBackend     = "client backend"
	pgauditFieldCount = 9
	// A statement is judged by the next line of its session, which may never come
	// if the client went quiet. After this long its outcome is reported as unknown.
	holdTimeout     = 5 * time.Second
	maxHeldSessions = 10_000
)

// contextSetting matches the SDK's statement exactly. Its value goes to the
// verifier and nowhere else, and no other SET statement is looked at.
var contextSetting = regexp.MustCompile(`^SET LOCAL dg\.ctx = '([0-9A-Za-z_.-]+)'$`)

// pgEntry lists only the jsonlog fields in use. Message, detail and hint can quote
// row values, so message is read solely to recognize pgAudit and session lines,
// and detail is not decoded at all.
type pgEntry struct {
	Timestamp   string `json:"timestamp"`
	User        string `json:"user"`
	Database    string `json:"dbname"`
	RemoteHost  string `json:"remote_host"`
	SessionID   string `json:"session_id"`
	VXID        string `json:"vxid"`
	Severity    string `json:"error_severity"`
	StateCode   string `json:"state_code"`
	Message     string `json:"message"`
	Statement   string `json:"statement"`
	BackendType string `json:"backend_type"`
}

type heldRecord struct {
	record Record
	at     fileCursor
	seen   time.Time
	// order counts lines as fed. Lines arrive in log order across rotated files,
	// whose offsets cannot be compared with each other.
	order uint64
}

// sessionContext remembers the signed context set in a transaction.
type sessionContext struct {
	transaction string
	token       string
}

// postgresParser reads jsonlog with pgAudit. pgAudit writes its line before the
// statement runs, so a line proves nothing about the outcome: the verdict comes
// from the session's next line. Until then the record is held back.
type postgresParser struct {
	held     map[string]*heldRecord
	contexts map[string]sessionContext
	now      func() time.Time
	fed      uint64
	// location is log_timezone. A timestamp names only its abbreviation, which
	// resolves to an offset within that zone and is ambiguous outside it.
	location *time.Location
}

func newPostgresParser() *postgresParser {
	return &postgresParser{
		held: map[string]*heldRecord{}, contexts: map[string]sessionContext{}, now: time.Now, location: time.UTC,
	}
}

func (p *postgresParser) setLocation(location *time.Location) { p.location = location }

func (p *postgresParser) feed(line []byte, at fileCursor) ([]Record, bool) {
	var entry pgEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return nil, false
	}
	if entry.BackendType != clientBackend {
		return nil, true
	}
	switch {
	case strings.HasPrefix(entry.Message, pgauditPrefix):
		return p.audit(&entry, at)
	case entry.Severity == "ERROR" || entry.Severity == "FATAL":
		return p.failure(&entry, at), true
	case strings.HasPrefix(entry.Message, "disconnection:"):
		delete(p.contexts, entry.SessionID)
		return p.settle(entry.SessionID), true
	case strings.HasPrefix(entry.Message, "connection authorized:"):
		return []Record{p.login(&entry, at, agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS)}, true
	default:
		return nil, true
	}
}

func (p *postgresParser) audit(entry *pgEntry, at fileCursor) ([]Record, bool) {
	fields, err := parseAuditFields(entry.Message[len(pgauditPrefix):])
	if err != nil {
		return nil, false
	}
	class, statement := fields[3], fields[7]
	if class == "MISC" {
		if match := contextSetting.FindStringSubmatch(statement); match != nil {
			if len(p.contexts) >= maxHeldSessions {
				// Without disconnection lines nothing else ends a session. Forgetting
				// contexts only downgrades identity to the database login.
				clear(p.contexts)
			}
			p.contexts[entry.SessionID] = sessionContext{transaction: entry.VXID, token: match[1]}
		}
		return nil, true
	}
	settled := p.settle(entry.SessionID)
	record := p.base(entry, at)
	record.Statement = NewStatement(statement)
	record.ContextToken = p.contextOf(entry)
	p.fed++
	settled = append(settled, p.hold(entry.SessionID, &heldRecord{record: record, at: at, seen: p.now(), order: p.fed})...)
	return settled, true
}

func parseAuditFields(text string) ([]string, error) {
	reader := csv.NewReader(strings.NewReader(text))
	reader.FieldsPerRecord = pgauditFieldCount
	reader.LazyQuotes = false
	return reader.Read()
}

func (p *postgresParser) contextOf(entry *pgEntry) string {
	if current, ok := p.contexts[entry.SessionID]; ok && current.transaction == entry.VXID {
		return current.token
	}
	return ""
}

func (p *postgresParser) base(entry *pgEntry, at fileCursor) Record {
	return Record{
		Position:      at.position(),
		Time:          parsePostgresTime(entry.Timestamp, p.location),
		Principal:     entry.User,
		ClientAddress: entry.RemoteHost,
		Session:       entry.SessionID,
		Transaction:   entry.VXID,
		Status:        agentv1.ExecutionStatus_EXECUTION_STATUS_UNKNOWN,
	}
}

func parsePostgresTime(value string, location *time.Location) time.Time {
	parsed, err := time.ParseInLocation(pgTimeLayout, value, location)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

// hold keeps a record until its outcome is known. At capacity the oldest record
// is released with an unknown outcome rather than dropped: losing the verdict is
// acceptable, losing the access is not.
func (p *postgresParser) hold(session string, record *heldRecord) []Record {
	var released []Record
	if len(p.held) >= maxHeldSessions {
		oldest := ""
		for key, item := range p.held {
			if oldest == "" || item.seen.Before(p.held[oldest].seen) {
				oldest = key
			}
		}
		released = append(released, p.held[oldest].record)
		delete(p.held, oldest)
	}
	p.held[session] = record
	return released
}

// settle completes a held record: a new line in the session means the previous
// statement finished without an error line.
func (p *postgresParser) settle(session string) []Record {
	item, found := p.held[session]
	if !found {
		return nil
	}
	delete(p.held, session)
	item.record.Status = agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS
	return []Record{item.record}
}

func (p *postgresParser) failure(entry *pgEntry, at fileCursor) []Record {
	if item, found := p.held[entry.SessionID]; found {
		delete(p.held, entry.SessionID)
		item.record.Status = agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE
		item.record.ErrorCode = entry.StateCode
		return []Record{item.record}
	}
	if strings.HasPrefix(entry.StateCode, "28") {
		return []Record{p.login(entry, at, agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE)}
	}
	if entry.Statement == "" {
		return nil
	}
	// Rejected before execution, so pgAudit wrote nothing: permission and syntax
	// errors arrive only as this line.
	record := p.base(entry, at)
	record.Statement = NewStatement(entry.Statement)
	record.Status = agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE
	record.ErrorCode = entry.StateCode
	record.ContextToken = p.contextOf(entry)
	return []Record{record}
}

func (p *postgresParser) login(entry *pgEntry, at fileCursor, status agentv1.ExecutionStatus) Record {
	record := p.base(entry, at)
	record.Kind = KindLogin
	record.Status = status
	record.ErrorCode = entry.StateCode
	return record
}

// flush releases records whose session stayed silent, with an unknown outcome.
func (p *postgresParser) flush() []Record {
	var expired []Record
	deadline := p.now().Add(-holdTimeout)
	for session, item := range p.held {
		if item.seen.Before(deadline) {
			delete(p.held, session)
			expired = append(expired, item.record)
		}
	}
	return expired
}

func (p *postgresParser) oldestHeld() (fileCursor, bool) {
	var oldest *heldRecord
	for _, item := range p.held {
		if oldest == nil || item.order < oldest.order {
			oldest = item
		}
	}
	if oldest == nil {
		return fileCursor{}, false
	}
	return oldest.at, true
}

// state is empty: every line carries user and session, and contexts are bound to
// a transaction that a restart replays from the held position anyway.
func (*postgresParser) state() json.RawMessage { return nil }

func (*postgresParser) restore(json.RawMessage) {}

func (p *postgresParser) reset() {
	clear(p.held)
	clear(p.contexts)
}
