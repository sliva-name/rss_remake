// Package queue is the agent's durable outbox. Audit events and the log position
// they came from are committed in one transaction, so after a crash the agent
// neither loses events nor re-reads what it already stored.
package queue

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

const (
	keyBytes        = 32
	sequenceBytes   = 8
	fileMode        = 0o600
	openTimeout     = 5 * time.Second
	bucketEvents    = "events"
	bucketCursors   = "cursors"
	bucketMeta      = "meta"
	metaPendingSize = "pending_bytes"
)

// ErrFull means the capacity is reached. The caller must not advance its log
// position, so nothing is lost while the source still retains the log.
var ErrFull = errors.New("queue is full")

// Item is a stored event.
type Item struct {
	Sequence uint64
	Event    *agentv1.AuditEvent
}

// Stats describes the backlog.
type Stats struct {
	PendingEvents uint64
	PendingBytes  uint64
	CapacityBytes uint64
}

// Queue is safe for concurrent use.
type Queue struct {
	db       *bolt.DB
	aead     cipher.AEAD
	capacity uint64
}

// Open creates or opens the queue in directory. Events hold no raw values; the
// encryption is defense in depth for backups and copied disks, because the key
// lives next to the data.
func Open(directory string, capacity uint64) (*Queue, error) {
	key, err := loadKey(filepath.Join(directory, "queue.key"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create queue cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create queue cipher: %w", err)
	}
	db, err := bolt.Open(filepath.Join(directory, "queue.db"), fileMode, &bolt.Options{Timeout: openTimeout})
	if err != nil {
		return nil, fmt.Errorf("open queue: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{bucketEvents, bucketCursors, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("prepare queue: %w", err), db.Close())
	}
	return &Queue{db: db, aead: aead, capacity: capacity}, nil
}

func loadKey(path string) ([]byte, error) {
	key, err := os.ReadFile(filepath.Clean(path))
	if err == nil {
		if len(key) != keyBytes {
			return nil, errors.New("queue key has a wrong size")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read queue key: %w", err)
	}
	key = make([]byte, keyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate queue key: %w", err)
	}
	if err := os.WriteFile(path, key, fileMode); err != nil {
		return nil, fmt.Errorf("write queue key: %w", err)
	}
	return key, nil
}

// Close flushes and closes the file.
func (q *Queue) Close() error { return q.db.Close() }

func sequenceKey(sequence uint64) []byte {
	key := make([]byte, sequenceBytes)
	binary.BigEndian.PutUint64(key, sequence)
	return key
}

func (q *Queue) seal(sequence uint64, event *agentv1.AuditEvent) ([]byte, error) {
	plain, err := proto.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("encode event: %w", err)
	}
	nonce := make([]byte, q.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	// Binding the sequence stops a record being replayed under another position.
	return q.aead.Seal(nonce, nonce, plain, sequenceKey(sequence)), nil
}

func (q *Queue) open(key, sealed []byte) (*agentv1.AuditEvent, error) {
	size := q.aead.NonceSize()
	if len(sealed) < size {
		return nil, errors.New("queue record is truncated")
	}
	plain, err := q.aead.Open(nil, sealed[:size], sealed[size:], key)
	if err != nil {
		return nil, fmt.Errorf("decrypt queue record: %w", err)
	}
	event := &agentv1.AuditEvent{}
	if err := proto.Unmarshal(plain, event); err != nil {
		return nil, fmt.Errorf("decode queue record: %w", err)
	}
	return event, nil
}

func readSize(tx *bolt.Tx) uint64 {
	value := tx.Bucket([]byte(bucketMeta)).Get([]byte(metaPendingSize))
	if len(value) != sequenceBytes {
		return 0
	}
	return binary.BigEndian.Uint64(value)
}

func writeSize(tx *bolt.Tx, size uint64) error {
	return tx.Bucket([]byte(bucketMeta)).Put([]byte(metaPendingSize), sequenceKey(size))
}

// Commit stores events and the new cursor atomically. It returns ErrFull without
// storing anything if the events do not fit.
func (q *Queue) Commit(source string, cursor []byte, events []*agentv1.AuditEvent) error {
	return q.commit(source, cursor, events, q.capacity)
}

// CommitGap stores events past the capacity. A gap record reports that data was
// lost, and a full queue is exactly when it must not be lost itself.
func (q *Queue) CommitGap(source string, cursor []byte, events []*agentv1.AuditEvent) error {
	return q.commit(source, cursor, events, ^uint64(0))
}

func (q *Queue) commit(source string, cursor []byte, events []*agentv1.AuditEvent, limit uint64) error {
	return q.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketEvents))
		size := readSize(tx)
		for _, event := range events {
			sequence, err := bucket.NextSequence()
			if err != nil {
				return err
			}
			sealed, err := q.seal(sequence, event)
			if err != nil {
				return err
			}
			size += uint64(len(sealed))
			if size > limit {
				return ErrFull
			}
			if err := bucket.Put(sequenceKey(sequence), sealed); err != nil {
				return err
			}
		}
		if err := writeSize(tx, size); err != nil {
			return err
		}
		if cursor == nil {
			return nil
		}
		return tx.Bucket([]byte(bucketCursors)).Put([]byte(source), cursor)
	})
}

// Cursor returns the stored position of source, or nil.
func (q *Queue) Cursor(source string) ([]byte, error) {
	var cursor []byte
	err := q.db.View(func(tx *bolt.Tx) error {
		if value := tx.Bucket([]byte(bucketCursors)).Get([]byte(source)); value != nil {
			cursor = append([]byte{}, value...)
		}
		return nil
	})
	return cursor, err
}

// Peek returns the oldest events without removing them.
func (q *Queue) Peek(maxEvents int, maxBytes uint64) ([]Item, error) {
	var items []Item
	err := q.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket([]byte(bucketEvents)).Cursor()
		var size uint64
		for key, sealed := cursor.First(); key != nil && len(items) < maxEvents; key, sealed = cursor.Next() {
			size += uint64(len(sealed))
			if size > maxBytes && len(items) > 0 {
				break
			}
			event, err := q.open(key, sealed)
			if err != nil {
				return err
			}
			items = append(items, Item{Sequence: binary.BigEndian.Uint64(key), Event: event})
		}
		return nil
	})
	return items, err
}

// Ack removes delivered events.
func (q *Queue) Ack(sequences []uint64) error {
	return q.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketEvents))
		size := readSize(tx)
		for _, sequence := range sequences {
			key := sequenceKey(sequence)
			value := bucket.Get(key)
			if value == nil {
				continue
			}
			size -= min(size, uint64(len(value)))
			if err := bucket.Delete(key); err != nil {
				return err
			}
		}
		return writeSize(tx, size)
	})
}

// Stats reports the backlog.
func (q *Queue) Stats() (Stats, error) {
	stats := Stats{CapacityBytes: q.capacity}
	err := q.db.View(func(tx *bolt.Tx) error {
		stats.PendingEvents = uint64(tx.Bucket([]byte(bucketEvents)).Stats().KeyN)
		stats.PendingBytes = readSize(tx)
		return nil
	})
	return stats, err
}

// SetMeta stores a small value that must survive restarts.
func (q *Queue) SetMeta(key string, value []byte) error {
	return q.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketMeta)).Put([]byte("user/"+key), value)
	})
}

// Meta reads a value stored by SetMeta.
func (q *Queue) Meta(key string) ([]byte, error) {
	var value []byte
	err := q.db.View(func(tx *bolt.Tx) error {
		if stored := tx.Bucket([]byte(bucketMeta)).Get([]byte("user/" + key)); stored != nil {
			value = append([]byte{}, stored...)
		}
		return nil
	})
	return value, err
}
