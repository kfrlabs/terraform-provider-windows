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

// ============================================================================
// HELPERS POUR L'ÉCHAPPEMENT POWERSHELL
// ============================================================================

// EscapePowerShellString échappe une chaîne pour une utilisation en PowerShell
// Remplace les guillemets simples par des guillemets doubles échappés
func EscapePowerShellString(s string) string {
	// Remplacer les guillemets simples par deux guillemets simples
	// C'est la façon standard d'échapper les guillemets en PowerShell
	return strings.ReplaceAll(s, "'", "''")
}

// QuotePowerShellString enveloppe et échappe une chaîne pour PowerShell
// Exemple: "test'value" -> "'test"value'"
func QuotePowerShellString(s string) string {
	return "'" + EscapePowerShellString(s) + "'"
}

// QuotePowerShellStringDouble enveloppe et échappe une chaîne avec des guillemets doubles
// Utile pour les chemins avec des variables d'environnement
// Exemple: "C:\Program Files" -> "\"C:\Program Files\""
func QuotePowerShellStringDouble(s string) string {
	// Échapper les guillemets doubles et les backticks
	escaped := strings.ReplaceAll(s, "`", "``")
	escaped = strings.ReplaceAll(escaped, "\"", "`\"")
	return "\"" + escaped + "\""
}

// SanitizePowerShellInput supprime les caractères dangereux
// (utiliser en dernier recours, préférer l'échappement)
func SanitizePowerShellInput(s string) string {
	dangerous := []string{";", "|", "&", "$", "`", "\n", "\r"}
	result := s
	for _, char := range dangerous {
		result = strings.ReplaceAll(result, char, "")
	}
	return result
}

// ValidatePowerShellArgument vérifie qu'un argument n'a pas de caractères dangereux
// Retourne une erreur si des patterns suspects sont trouvés
func ValidatePowerShellArgument(arg string) error {
	// Vérifier les patterns de commandes PowerShell
	suspiciousPatterns := []string{
		"|",   // Pipe
		";",   // Séparateur de commande
		"&",   // Opérateur ET
		"||",  // OU
		"&&",  // ET
		"$(",  // Substitution de commande
		"`",   // Backtick (escape PowerShell)
		"$()", // Substitution de commande
		"-",   // Drapeaux (peut être dangereux si combiné)
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(arg, pattern) {
			return fmt.Errorf("suspicious pattern '%s' found in argument", pattern)
		}
	}

	return nil
}

// ============================================================================
// EXECUTOR POWERSHELL SÉCURISÉ
// ============================================================================

// Executor gère l'exécution sécurisée des commandes PowerShell
type Executor struct {
	session *ssh.Session
	opts    *Options
}

// Options définit les options d'exécution PowerShell
type Options struct {
	NoProfile       bool
	NoLogo          bool
	NonInteractive  bool
	ExecutionPolicy string
}

// DefaultOptions retourne les options par défaut
func DefaultOptions() *Options {
	return &Options{
		NoProfile:       true,
		NoLogo:          true,
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

// Execute exécute une commande PowerShell de manière sécurisée
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

// buildCommand construit une commande PowerShell encodée (sécurisée)
func (e *Executor) buildCommand(command string) string {
	var cmdBuilder strings.Builder

	cmdBuilder.WriteString("powershell")

	if e.opts.NoLogo {
		cmdBuilder.WriteString(" -NoLogo")
	}
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

// ============================================================================
// BUILDERS DE COMMANDES POWERSHELL SÉCURISÉES
// ============================================================================

// CommandBuilder aide à construire des commandes PowerShell de manière sécurisée
type CommandBuilder struct {
	commands []string
}

// NewCommandBuilder crée un nouveau builder de commandes
func NewCommandBuilder() *CommandBuilder {
	return &CommandBuilder{
		commands: []string{},
	}
}

// AddCommand ajoute une commande au builder
func (cb *CommandBuilder) AddCommand(cmd string) *CommandBuilder {
	cb.commands = append(cb.commands, cmd)
	return cb
}

// Build retourne la commande combinée
func (cb *CommandBuilder) Build() string {
	return strings.Join(cb.commands, "; ")
}
