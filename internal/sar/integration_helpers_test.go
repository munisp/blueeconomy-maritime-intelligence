//go:build feedintegration || kafkaintegration

package sar

import "sync"

// migrateOnce applies the migration chain exactly once per test package run.
var migrateOnce sync.Once
