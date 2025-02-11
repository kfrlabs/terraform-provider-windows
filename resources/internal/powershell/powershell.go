package powershell

import (
	"bytes"
	"context"
	"fmt"
	"strings"

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
		return stdoutBuf.String(), stderrBuf.String(), err
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

	escapedCommand := strings.ReplaceAll(command, `"`, `\"`)
	cmdBuilder.WriteString(fmt.Sprintf(` -Command "%s"`, escapedCommand))

	return cmdBuilder.String()
}
