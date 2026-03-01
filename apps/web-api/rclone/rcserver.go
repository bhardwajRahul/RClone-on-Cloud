package rclone

import (
	"context"

	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/rc"

	// Side-effect imports to register RC methods and backends
	_ "github.com/rclone/rclone/backend/all"
	_ "github.com/rclone/rclone/fs/operations"
)

// Initialize loads the provided rclone config storage
// and sets up the internal RC system.
func Initialize(ctx context.Context, store config.Storage) error {
	config.SetData(store)

	// Enable RC and jobs globally
	rc.Opt.Enabled = true
	rc.Opt.NoAuth = true
	// jobs.SetOpt(&rc.Opt) // This is usually called by rcserver.Start, we should call it here

	// Since we are not using rcserver.Start, we should at least ensure jobs are ready
	// if we use them. jobs package initializes itself but we might want to sync options.
	return nil
}
