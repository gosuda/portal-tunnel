package utils

import "errors"

// ErrFileLocked indicates another process owns the file, or the platform does
// not support file locking. Closing the returned file releases its lock.
var ErrFileLocked = errors.New("file is locked or file locking is unsupported")
