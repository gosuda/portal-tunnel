package utils

import (
	"maps"
	"slices"
	"sync/atomic"
)

// Snapshot stores an immutable value snapshot for lock-free reads.
// Use a snapshot function when T contains mutable maps, slices, or pointers.
// Do not copy a Snapshot after first use.
type Snapshot[T any] struct {
	value    atomic.Pointer[T]
	snapshot func(T) T
}

func NewSnapshot[T any](initial T, snapshot ...func(T) T) *Snapshot[T] {
	s := &Snapshot[T]{}
	if len(snapshot) > 0 {
		s.snapshot = snapshot[0]
	}
	s.Store(initial)
	return s
}

func (s *Snapshot[T]) Load() T {
	if s == nil {
		var zero T
		return zero
	}
	value := s.value.Load()
	if value == nil {
		var zero T
		return zero
	}
	return s.snapshotValue(*value)
}

func (s *Snapshot[T]) Store(value T) {
	if s == nil {
		return
	}
	value = s.snapshotValue(value)
	s.value.Store(&value)
}

func (s *Snapshot[T]) snapshotValue(value T) T {
	if s != nil && s.snapshot != nil {
		return s.snapshot(value)
	}
	return value
}

// Update applies a copy-on-write update and stores the resulting snapshot.
// The update function may be called more than once under contention, so it
// must not perform side effects.
func (s *Snapshot[T]) Update(update func(T) T) T {
	if s == nil {
		var zero T
		return zero
	}
	for {
		currentPtr := s.value.Load()
		var current T
		if currentPtr != nil {
			current = s.snapshotValue(*currentPtr)
		}

		next := update(current)
		next = s.snapshotValue(next)
		if s.value.CompareAndSwap(currentPtr, &next) {
			return s.snapshotValue(next)
		}
	}
}

// UpdateIf stores the returned snapshot only when update returns true.
// The update function may be called more than once under contention, so it
// must not perform side effects.
func (s *Snapshot[T]) UpdateIf(update func(T) (T, bool)) (T, bool) {
	if s == nil {
		var zero T
		return zero, false
	}
	for {
		currentPtr := s.value.Load()
		var current T
		if currentPtr != nil {
			current = s.snapshotValue(*currentPtr)
		}

		next, ok := update(current)
		if !ok {
			return current, false
		}
		next = s.snapshotValue(next)
		if s.value.CompareAndSwap(currentPtr, &next) {
			return s.snapshotValue(next), true
		}
	}
}

// UpdateCopy copies the current snapshot, applies a local mutation to the copy,
// and stores the copy. The update function may be called more than once under
// contention, so it must not perform side effects.
func (s *Snapshot[T]) UpdateCopy(update func(*T)) T {
	return s.Update(func(current T) T {
		next := current
		if update != nil {
			update(&next)
		}
		return next
	})
}

func CloneSlice[T any](values []T) []T {
	return slices.Clone(values)
}

func CloneMap[K comparable, V any](values map[K]V) map[K]V {
	return maps.Clone(values)
}

func ClonePtr[T any](value *T) *T {
	if value == nil {
		return nil
	}
	next := *value
	return &next
}
