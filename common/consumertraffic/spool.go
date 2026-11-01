package consumertraffic

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/google/uuid"
	panel "github.com/wyx2685/v2node/api/v2board"
)

const maxSamples = 100000

type diskState struct {
	Version int                          `json:"version"`
	Batches []panel.ConsumerTrafficBatch `json:"batches"`
}
type Spool struct {
	mu      sync.Mutex
	path    string
	batches []panel.ConsumerTrafficBatch
	dirty   bool
}

func Open(path string) (*Spool, error) {
	s := &Spool{path: path, batches: []panel.ConsumerTrafficBatch{}}
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, 32*1024*1024+1))
		if err != nil {
			return nil, err
		}
		if len(raw) > 32*1024*1024 {
			return nil, errors.New("consumer traffic spool too large")
		}
		var state diskState
		if err = json.Unmarshal(raw, &state); err != nil || state.Version != 1 {
			return nil, errors.New("consumer traffic spool is invalid")
		}
		count := 0
		ids := map[string]bool{}
		for _, batch := range state.Batches {
			if err = validate(batch); err != nil {
				return nil, err
			}
			if ids[batch.ID] {
				return nil, errors.New("duplicate batch in consumer spool")
			}
			ids[batch.ID] = true
			count += len(batch.Samples)
		}
		if count > maxSamples {
			return nil, errors.New("consumer traffic spool limit exceeded")
		}
		s.batches = state.Batches
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Prove persistence works before activating a C credential, including after a restart.
	if err = s.save(); err != nil {
		return nil, err
	}
	return s, nil
}
func validate(batch panel.ConsumerTrafficBatch) error {
	if _, err := uuid.Parse(batch.ID); err != nil {
		return errors.New("invalid traffic batch id")
	}
	if batch.ObservedAt.IsZero() || len(batch.Samples) < 1 || len(batch.Samples) > 1000 {
		return errors.New("invalid traffic batch")
	}
	ids := map[string]bool{}
	for _, sample := range batch.Samples {
		id, err := uuid.Parse(sample.LeaseID)
		if err != nil || ids[id.String()] || sample.Upload < 0 || sample.Download < 0 {
			return errors.New("invalid traffic sample")
		}
		ids[id.String()] = true
	}
	return nil
}
func copyBatch(batch panel.ConsumerTrafficBatch) panel.ConsumerTrafficBatch {
	batch.Samples = slices.Clone(batch.Samples)
	return batch
}
func (s *Spool) Add(batches []panel.ConsumerTrafficBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	ids := map[string]bool{}
	for _, batch := range s.batches {
		count += len(batch.Samples)
		ids[batch.ID] = true
	}
	for _, batch := range batches {
		if err := validate(batch); err != nil {
			return err
		}
		if ids[batch.ID] {
			return errors.New("duplicate consumer traffic batch")
		}
		ids[batch.ID] = true
		count += len(batch.Samples)
	}
	if count > maxSamples {
		return errors.New("consumer traffic spool limit exceeded")
	}
	for _, batch := range batches {
		s.batches = append(s.batches, copyBatch(batch))
	}
	return s.save()
}

func (s *Spool) Room(samples int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := samples
	for _, batch := range s.batches {
		count += len(batch.Samples)
	}
	return !s.dirty && count <= maxSamples
}
func (s *Spool) First() (panel.ConsumerTrafficBatch, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.batches) == 0 {
		return panel.ConsumerTrafficBatch{}, false
	}
	return copyBatch(s.batches[0]), true
}
func (s *Spool) CanRenew() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.dirty && len(s.batches) == 0
}
func (s *Spool) Ack(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.batches) == 0 || s.batches[0].ID != id {
		return errors.New("consumer traffic acknowledgement out of order")
	}
	s.batches = s.batches[1:]
	return s.save()
}
func (s *Spool) RetrySave() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.save()
}
func (s *Spool) save() (err error) {
	s.dirty = true
	dir := filepath.Dir(s.path)
	if err = os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	raw, err := json.Marshal(diskState{Version: 1, Batches: s.batches})
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".consumer-traffic-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	if err = parent.Sync(); err != nil {
		return fmt.Errorf("sync consumer traffic directory: %w", err)
	}
	s.dirty = false
	return nil
}
