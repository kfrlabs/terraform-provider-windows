package powershell

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"
)

// Executor gère l'exécution des commandes PowerShell
type Executor struct {
	session *ssh.Session
	opts    *Options
}

// Options définit les options d'exécution PowerShell
type Options struct {
	NoProfile       bool
	NonInteractive  bool
	ExecutionPolicy string
}

// DefaultOptions retourne les options par défaut
func DefaultOptions() *Options {
	return &Options{
		NoProfile:       true,
		NonInteractive:  true,
		ExecutionPolicy: "Bypass",
	}
}

// NewExecutor crée un nouvel exécuteur PowerShell
func NewExecutor(session *ssh.Session, opts *Options) *Executor {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Executor{
		session: session,
		opts:    opts,
	}
}

// Execute exécute une commande PowerShell
func (e *Executor) Execute(ctx context.Context, command string) (string, string, error) {
	var stdoutBuf, stderrBuf bytes.Buffer
	e.session.Stdout = &stdoutBuf
	e.session.Stderr = &stderrBuf

	psCommand := e.buildCommand(command)

	errCh := make(chan error, 1)
	go func() {
		errCh <- e.session.Run(psCommand)
	}()

	select {
	case <-ctx.Done():
		e.session.Signal(ssh.SIGTERM)
		return "", "", ctx.Err()
	case err := <-errCh:
		return strings.TrimRight(stdoutBuf.String(), "\r\n"), strings.TrimRight(stderrBuf.String(), "\r\n"), err
	}
}

func (e *Executor) buildCommand(command string) string {
	var cmdBuilder strings.Builder

	cmdBuilder.WriteString("pwsh")

	if e.opts.NoProfile {
		cmdBuilder.WriteString(" -NoProfile")
	}
	if e.opts.NonInteractive {
		cmdBuilder.WriteString(" -NonInteractive")
	}
	if e.opts.ExecutionPolicy != "" {
		cmdBuilder.WriteString(fmt.Sprintf(" -ExecutionPolicy %s", e.opts.ExecutionPolicy))
	}

	// Convertir la commande en UTF-16LE (requis par PowerShell) avant l'encodage Base64
	utf16Command := utf16.Encode([]rune(command))
	utf16Bytes := make([]byte, len(utf16Command)*2)
	for i, r := range utf16Command {
		binary.LittleEndian.PutUint16(utf16Bytes[i*2:], r)
	}

	// Encoder en Base64
	encodedCommand := base64.StdEncoding.EncodeToString(utf16Bytes)
	cmdBuilder.WriteString(" -EncodedCommand ")
	cmdBuilder.WriteString(encodedCommand)

	return cmdBuilder.String()
}
