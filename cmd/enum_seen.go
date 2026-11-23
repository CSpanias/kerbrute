package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
)

var seenBucket = []byte("seen")

type enumSeen struct {
	dir   string
	db    *bolt.DB
	tx    *bolt.Tx
	count int
}

func newEnumSeen() (*enumSeen, error) {
	dir, err := os.MkdirTemp("", "kerbrute-userenum-")
	if err != nil {
		return nil, fmt.Errorf("create temporary username store: %w", err)
	}
	db, err := bolt.Open(filepath.Join(dir, "seen.db"), 0600, &bolt.Options{NoSync: true})
	if err != nil {
		if cleanupErr := os.RemoveAll(dir); cleanupErr != nil {
			return nil, fmt.Errorf("open temporary username store: %v; remove %q: %w", err, dir, cleanupErr)
		}
		return nil, fmt.Errorf("open temporary username store: %w", err)
	}
	s := &enumSeen{dir: dir, db: db}
	if err := s.begin(); err != nil {
		if cleanupErr := s.close(); cleanupErr != nil {
			return nil, fmt.Errorf("initialize username store: %v; cleanup: %w", err, cleanupErr)
		}
		return nil, fmt.Errorf("initialize username store: %w", err)
	}
	return s, nil
}

func (s *enumSeen) begin() error {
	tx, err := s.db.Begin(true)
	if err != nil {
		return err
	}
	s.tx = tx
	_, err = tx.CreateBucketIfNotExists(seenBucket)
	return err
}

func (s *enumSeen) add(username string) (bool, error) {
	key := []byte(strings.ToLower(username))
	bucket := s.tx.Bucket(seenBucket)
	if bucket.Get(key) != nil {
		return false, nil
	}
	if err := bucket.Put(key, []byte{1}); err != nil {
		return false, fmt.Errorf("store username for duplicate detection: %w", err)
	}
	s.count++
	if s.count == 5000 {
		err := s.tx.Commit()
		s.tx = nil
		if err != nil {
			return false, fmt.Errorf("commit username store: %w", err)
		}
		s.count = 0
		if err := s.begin(); err != nil {
			return false, fmt.Errorf("continue username store: %w", err)
		}
	}
	return true, nil
}

func (s *enumSeen) close() error {
	var errs []error
	if s.tx != nil {
		if err := s.tx.Rollback(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.db.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := os.RemoveAll(s.dir); err != nil {
		errs = append(errs, fmt.Errorf("remove temporary username store %q: %w", s.dir, err))
	}
	if len(errs) != 0 {
		return fmt.Errorf("close username store: %v", errs)
	}
	return nil
}
