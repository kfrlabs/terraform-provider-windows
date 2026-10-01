// Package winclient: windows_directory CRUD implementation over SSH.
//
// Transport invariants:
//   - Every user-supplied path reaches a script only through psQuote.
//   - Scripts are sent via -EncodedCommand by Client.RunPowerShell.
//
// Security invariants:
//   - Every user-supplied string reaching a script goes through psQuote.
package winclient

import (
	"context"
	"errors"
)

// Compile-time assertion: DirectoryClientImpl satisfies DirectoryClient.
var _ DirectoryClient = (*DirectoryClientImpl)(nil)

// DirectoryClientImpl is the PowerShell/SSH-backed DirectoryClient.
type DirectoryClientImpl struct {
	c *Client
}

// NewDirectoryClient constructs a DirectoryClientImpl wrapping the given SSH Client.
func NewDirectoryClient(c *Client) *DirectoryClientImpl {
	return &DirectoryClientImpl{c: c}
}

// Create implements DirectoryClient.Create.
func (d *DirectoryClientImpl) Create(_ context.Context, _ DirectoryInput) (*DirectoryState, error) {
	return nil, errors.New("directory: not implemented")
}

// Read implements DirectoryClient.Read.
func (d *DirectoryClientImpl) Read(_ context.Context, _ string) (*DirectoryState, error) {
	return nil, errors.New("directory: not implemented")
}

// Update implements DirectoryClient.Update.
func (d *DirectoryClientImpl) Update(_ context.Context, _ string, _ []string) (*DirectoryState, error) {
	return nil, errors.New("directory: not implemented")
}

// Delete implements DirectoryClient.Delete.
func (d *DirectoryClientImpl) Delete(_ context.Context, _ string, _ bool) error {
	return errors.New("directory: not implemented")
}
