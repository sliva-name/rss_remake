package collector

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

var (
	generalLine    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(\d+)\s([A-Za-z][A-Za-z ]*?)\t(.*)$`)
	generalConnect = regexp.MustCompile(`^([^@\s]+)@(\S*) on `)
	accessDenied   = regexp.MustCompile(`^Access denied for user '([^']*)'@'([^']*)'`)
)

type generalSession struct {
	Principal string `json:"principal"`
	Address   string `json:"address"`
}

// generalParser reads the MySQL general log. It is the only auditing MySQL
// Community has, and it writes before execution with no outcome, so every record
// stays at status unknown. A statement may span lines, so a record is complete
// only when the next header arrives.
type generalParser struct {
	sessions map[string]generalSession
	current  *heldRecord
	builder  strings.Builder
	now      func() time.Time
}

const maxGeneralSessions = 100_000

func newGeneralParser() *generalParser {
	return &generalParser{sessions: map[string]generalSession{}, now: time.Now}
}

func (p *generalParser) feed(line []byte, at fileCursor) ([]Record, bool) {
	match := generalLine.FindSubmatch(line)
	if match == nil {
		if p.current == nil {
			// Server banner lines at the start of the file carry no timestamp.
			return nil, true
		}
		p.builder.WriteByte('\n')
		p.builder.Write(line)
		return nil, true
	}
	completed := p.complete()
	thread, command, argument := string(match[2]), string(match[3]), string(match[4])
	timestamp, err := time.Parse(time.RFC3339Nano, string(match[1]))
	if err != nil {
		return completed, false
	}
	switch command {
	case "Connect":
		completed = append(completed, p.connect(thread, argument, timestamp, at)...)
	case "Quit":
		delete(p.sessions, thread)
	case "Query", "Execute":
		session := p.sessions[thread]
		p.builder.Reset()
		p.builder.WriteString(argument)
		p.current = &heldRecord{at: at, seen: p.now(), record: Record{
			Position: at.position(), Time: timestamp, Principal: session.Principal,
			ClientAddress: session.Address, Session: thread,
			Status: agentv1.ExecutionStatus_EXECUTION_STATUS_UNKNOWN,
		}}
	}
	return completed, true
}

func (p *generalParser) connect(thread, argument string, timestamp time.Time, at fileCursor) []Record {
	if denied := accessDenied.FindStringSubmatch(argument); denied != nil {
		return []Record{{
			Kind: KindLogin, Position: at.position(), Time: timestamp, Principal: denied[1],
			ClientAddress: denied[2], Session: thread, Status: agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE,
		}}
	}
	match := generalConnect.FindStringSubmatch(argument)
	if match == nil {
		return nil
	}
	if len(p.sessions) >= maxGeneralSessions {
		clear(p.sessions)
	}
	p.sessions[thread] = generalSession{Principal: match[1], Address: match[2]}
	return []Record{{
		Kind: KindLogin, Position: at.position(), Time: timestamp, Principal: match[1],
		ClientAddress: match[2], Session: thread, Status: agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
	}}
}

func (p *generalParser) complete() []Record {
	if p.current == nil {
		return nil
	}
	record := p.current.record
	record.Statement = NewStatement(p.builder.String())
	p.current = nil
	p.builder.Reset()
	return []Record{record}
}

func (p *generalParser) flush() []Record {
	if p.current != nil && p.now().Sub(p.current.seen) > holdTimeout {
		return p.complete()
	}
	return nil
}

func (p *generalParser) oldestHeld() (fileCursor, bool) {
	if p.current == nil {
		return fileCursor{}, false
	}
	return p.current.at, true
}

// state keeps logins, because statement lines name only a thread: without it a
// restart would turn every open session into an unknown principal.
func (p *generalParser) state() json.RawMessage {
	encoded, err := json.Marshal(p.sessions)
	if err != nil {
		return nil
	}
	return encoded
}

func (p *generalParser) restore(state json.RawMessage) {
	if len(state) > 0 {
		// A corrupt state only loses attribution of open sessions.
		_ = json.Unmarshal(state, &p.sessions)
	}
}

func (p *generalParser) reset() {
	p.current = nil
	p.builder.Reset()
}

const (
	mariaFieldsBeforeQuery = 8
	mariaTimeLayout        = "20060102 15:04:05"
	opConnect              = "CONNECT"
	opFailedConnect        = "FAILED_CONNECT"
	opDisconnect           = "DISCONNECT"
)

// mariadbParser reads server_audit, whose lines are complete: each carries the
// outcome, so nothing is held back.
type mariadbParser struct{}

func (mariadbParser) feed(line []byte, at fileCursor) ([]Record, bool) {
	fields := bytes.SplitN(line, []byte(","), mariaFieldsBeforeQuery)
	if len(fields) != mariaFieldsBeforeQuery {
		return nil, false
	}
	timestamp, err := time.Parse(mariaTimeLayout, string(fields[0]))
	if err != nil {
		return nil, false
	}
	principal, address, session, operation := string(fields[2]), string(fields[3]), string(fields[4]), string(fields[6])
	record := Record{
		Position: at.position(), Time: timestamp.UTC(), Principal: principal,
		ClientAddress: address, Session: session,
	}
	remainder := fields[7]
	switch operation {
	case opConnect, opFailedConnect:
		record.Kind = KindLogin
		record.Status = agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS
		if operation == opFailedConnect {
			record.Status = agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE
		}
		return []Record{record}, true
	case opDisconnect:
		return nil, true
	}
	if !strings.HasPrefix(operation, "QUERY") {
		return nil, true
	}
	statement, code, ok := mariaQuery(remainder)
	if !ok {
		return nil, false
	}
	record.Statement = NewStatement(statement)
	record.Status = agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS
	if code != 0 {
		record.Status = agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE
		record.ErrorCode = strconv.Itoa(code)
	}
	return []Record{record}, true
}

// mariaQuery splits "database,'statement',retcode". The statement is quoted with
// backslash escapes and may contain commas, so the numeric code is taken from the
// end and the database from the start.
func mariaQuery(remainder []byte) (string, int, bool) {
	start := bytes.IndexByte(remainder, '\'')
	end := bytes.LastIndexByte(remainder, '\'')
	if start < 0 || end <= start {
		return "", 0, false
	}
	code, err := strconv.Atoi(strings.TrimPrefix(string(remainder[end+1:]), ","))
	if err != nil {
		return "", 0, false
	}
	return unescapeMaria(remainder[start+1 : end]), code, true
}

func unescapeMaria(text []byte) string {
	var builder strings.Builder
	builder.Grow(len(text))
	for i := 0; i < len(text); i++ {
		if text[i] != '\\' || i+1 == len(text) {
			builder.WriteByte(text[i])
			continue
		}
		i++
		switch text[i] {
		case 'n':
			builder.WriteByte('\n')
		case 'r':
			builder.WriteByte('\r')
		case 't':
			builder.WriteByte('\t')
		default:
			builder.WriteByte(text[i])
		}
	}
	return builder.String()
}

func (mariadbParser) flush() []Record { return nil }

func (mariadbParser) oldestHeld() (fileCursor, bool) { return fileCursor{}, false }

func (mariadbParser) state() json.RawMessage { return nil }

func (mariadbParser) restore(json.RawMessage) {}

func (mariadbParser) reset() {}
