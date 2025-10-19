package cli

import (
	"context"
	"fmt"
)

const syncResultTemplate = `
=== Synchronization Result ===

✓ Synchronization completed successfully!

Summary:
  Pushed to server:   {{.PushedEntries}} entries
  Pulled from server: {{.PulledEntries}} entries
  Merged locally:     {{.MergedEntries}} entries
  {{- if gt .Conflicts 0 }}
  Conflicts resolved: {{.Conflicts}}
  {{- end }}
  {{- if gt .SkippedEntries 0 }}
  Skipped (errors):   {{.SkippedEntries}}
  {{- end }}

Your data is now synchronized with the server.
`

func (c *Cli) runSync(ctx context.Context) error {
	if c.authData == nil {
		return fmt.Errorf("not authenticated or encryption key not available")
	}

	if err := c.authService.EnsureTokenValid(ctx); err != nil {
		return fmt.Errorf("%w. Please login again", err)
	}

	authData, err := c.authService.GetAuthDecryptData(ctx)
	if err != nil {
		return fmt.Errorf("failed to get updated auth data: %w", err)
	}
	c.authData = authData

	c.io.Println("Starting synchronization with server...")

	result, err := c.syncService.Sync(ctx, c.authData.UserID, c.authData.AccessToken)
	if err != nil {
		return fmt.Errorf("synchronization failed: %w", err)
	}

	if err := c.printTemplate(syncResultTemplate, result); err != nil {
		return fmt.Errorf("failed to print sync result: %w", err)
	}

	return nil
}
