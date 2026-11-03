package collector

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

// maxLineBytes bounds memory for one log line. A longer line is skipped and
// counted, so one huge statement cannot exhaust the agent.
const maxLineBytes = 4 << 20

// fileCursor locates a read position. The inode, not the name, identifies the
// file, because rotation renames files under the reader.
type fileCursor struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

type logFile struct {
	path  string
	inode uint64
	size  int64
	info  os.FileInfo
}

func listFiles(pattern string) ([]logFile, error) {
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	files := make([]logFile, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, errors.New("log files need inode support")
		}
		files = append(files, logFile{path: path, inode: stat.Ino, size: info.Size(), info: info})
	}
	slices.SortFunc(files, func(a, b logFile) int {
		return cmp.Or(a.info.ModTime().Compare(b.info.ModTime()), cmp.Compare(b.path, a.path))
	})
	return files, nil
}

// tail reads complete lines across rotated files.
type tail struct {
	pattern string
	maxRead int64
}

type tailResult struct {
	position fileCursor
	lost     bool
}

// readFrom delivers complete lines after position. A nil position starts at the
// end of the newest file: history before installation is not audited.
func (t *tail) readFrom(position *fileCursor, visit func(line []byte, at fileCursor)) (tailResult, uint64, error) {
	files, err := listFiles(t.pattern)
	if err != nil {
		return tailResult{}, 0, fmt.Errorf("list audit logs: %w", err)
	}
	if len(files) == 0 {
		return tailResult{}, 0, os.ErrNotExist
	}
	if position == nil {
		newest := files[len(files)-1]
		return tailResult{position: fileCursor{Inode: newest.inode, Offset: newest.size}}, 0, nil
	}
	index, lost, current := locate(files, *position)
	result := tailResult{position: current, lost: lost}
	var skipped uint64
	remaining := t.maxRead
	for {
		consumed, oversized, err := readLines(files[index].path, &result.position, remaining, visit)
		if err != nil {
			return result, skipped, err
		}
		skipped += oversized
		remaining -= consumed
		if remaining <= 0 || index == len(files)-1 || result.position.Offset < files[index].size {
			return result, skipped, nil
		}
		index++
		result.position = fileCursor{Inode: files[index].inode}
	}
}

// locate finds where to continue. A file shorter than the offset was truncated in
// place, and a missing inode was rotated away; both mean unread records are gone.
func locate(files []logFile, position fileCursor) (int, bool, fileCursor) {
	for i := range files {
		if files[i].inode != position.Inode {
			continue
		}
		if files[i].size < position.Offset {
			return i, true, fileCursor{Inode: files[i].inode}
		}
		return i, false, position
	}
	return 0, true, fileCursor{Inode: files[0].inode}
}

// readLines stops at the last complete line, so a line still being written is
// picked up whole on the next read.
func readLines(path string, position *fileCursor, budget int64, visit func(line []byte, at fileCursor)) (int64, uint64, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return 0, 0, fmt.Errorf("open audit log: %w", err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Seek(position.Offset, io.SeekStart); err != nil {
		return 0, 0, fmt.Errorf("seek audit log: %w", err)
	}
	reader := bufio.NewReaderSize(file, maxLineBytes)
	var consumed int64
	var oversized uint64
	for consumed < budget {
		line, err := reader.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			skippedBytes, skipErr := skipLine(reader, int64(len(line)))
			if skipErr != nil {
				// The rest of the line is not written yet; retry from its start.
				return consumed, oversized, nil
			}
			oversized++
			consumed += skippedBytes
			position.Offset += skippedBytes
			continue
		case errors.Is(err, io.EOF):
			return consumed, oversized, nil
		case err != nil:
			return consumed, oversized, fmt.Errorf("read audit log: %w", err)
		}
		at := *position
		consumed += int64(len(line))
		position.Offset += int64(len(line))
		visit(line[:len(line)-1], at)
	}
	return consumed, oversized, nil
}

func skipLine(reader *bufio.Reader, already int64) (int64, error) {
	total := already
	for {
		chunk, err := reader.ReadSlice('\n')
		total += int64(len(chunk))
		if err == nil {
			return total, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return 0, err
		}
	}
}

func (c fileCursor) position() string {
	return fmt.Sprintf("%d:%d", c.Inode, c.Offset)
}

// lineParser turns log lines into records. It may hold records back until a later
// line completes them.
type lineParser interface {
	feed(line []byte, at fileCursor) ([]Record, bool)
	// flush returns records held longer than the patience of the reader.
	flush() []Record
	// oldestHeld is the earliest position not yet emitted, if any.
	oldestHeld() (fileCursor, bool)
	state() json.RawMessage
	restore(state json.RawMessage)
	// reset forgets everything held, for a replay from an earlier position.
	reset()
}

// fileReader adapts a tail and a parser to Reader.
type fileReader struct {
	tail   tail
	parser lineParser
	// live is where reading continues. The durable cursor can lag behind it while
	// the parser holds records, so a crash replays them instead of losing them.
	live     *fileCursor
	restored bool
}

type storedCursor struct {
	Position fileCursor      `json:"position"`
	State    json.RawMessage `json:"state,omitempty"`
}

const defaultReadBytes = 8 << 20

func newFileReader(pattern string, parser lineParser) *fileReader {
	return &fileReader{tail: tail{pattern: pattern, maxRead: defaultReadBytes}, parser: parser}
}

// locatedParser reads timestamps that mean nothing without the server's zone.
type locatedParser interface {
	lineParser
	setLocation(location *time.Location)
}

// zonedFileReader is a fileReader whose parser needs the server's time zone.
type zonedFileReader struct {
	*fileReader
	parser locatedParser
}

func newZonedFileReader(pattern string, parser locatedParser) *zonedFileReader {
	return &zonedFileReader{fileReader: newFileReader(pattern, parser), parser: parser}
}

func (r *zonedFileReader) setLocation(location *time.Location) { r.parser.setLocation(location) }

func (r *fileReader) resume(cursor []byte) error {
	if r.restored {
		return nil
	}
	r.restored = true
	if cursor == nil {
		return nil
	}
	var stored storedCursor
	if err := json.Unmarshal(cursor, &stored); err != nil {
		return fmt.Errorf("decode audit cursor: %w", err)
	}
	r.live = &stored.Position
	r.parser.restore(stored.State)
	return nil
}

// Rewind implements Reader.
func (r *fileReader) Rewind() {
	r.restored = false
	r.parser.reset()
}

// Read implements Reader.
func (r *fileReader) Read(_ context.Context, cursor []byte) (Batch, error) {
	if err := r.resume(cursor); err != nil {
		return Batch{}, err
	}
	var batch Batch
	result, oversized, err := r.tail.readFrom(r.live, func(line []byte, at fileCursor) {
		records, ok := r.parser.feed(line, at)
		if !ok {
			batch.Unparseable++
			return
		}
		batch.Records = append(batch.Records, records...)
	})
	if err != nil {
		return Batch{}, err
	}
	batch.Unparseable += oversized
	batch.Records = append(batch.Records, r.parser.flush()...)
	r.live = &result.position
	durable := result.position
	if held, ok := r.parser.oldestHeld(); ok {
		durable = held
	}
	batch.Cursor, err = json.Marshal(storedCursor{Position: durable, State: r.parser.state()})
	if err != nil {
		return Batch{}, fmt.Errorf("encode audit cursor: %w", err)
	}
	if result.lost {
		batch.Gap = lostLogGap()
	}
	return batch, nil
}
