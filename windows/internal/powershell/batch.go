package powershell

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ============================================================================
// BATCH COMMAND BUILDER
// ============================================================================

// BatchCommandBuilder builds multiple PowerShell commands efficiently
// It minimizes the overhead of multiple SSH round-trips by combining
// commands into a single execution
type BatchCommandBuilder struct {
	commands     []string
	separator    string
	errorAction  string
	outputFormat OutputFormat
	useJSON      bool
}

// OutputFormat defines how batch results should be formatted
type OutputFormat int

const (
	// OutputNone - no output capture
	OutputNone OutputFormat = iota
	// OutputArray - capture output as JSON array
	OutputArray
	// OutputObject - capture output as JSON object with keys
	OutputObject
	// OutputRaw - capture raw output separated by newlines
	OutputRaw
	// OutputSeparator - capture output with custom separator
	OutputSeparator
)

// NewBatchCommandBuilder creates a new batch command builder
func NewBatchCommandBuilder() *BatchCommandBuilder {
	return &BatchCommandBuilder{
		commands:     make([]string, 0),
		separator:    "; ",
		errorAction:  "Stop",
		outputFormat: OutputNone,
		useJSON:      false,
	}
}

// NewJSONBatchCommandBuilder creates a batch builder that outputs JSON
func NewJSONBatchCommandBuilder() *BatchCommandBuilder {
	return &BatchCommandBuilder{
		commands:     make([]string, 0),
		separator:    "; ",
		errorAction:  "Stop",
		outputFormat: OutputArray,
		useJSON:      true,
	}
}

// Add adds a command to the batch
func (b *BatchCommandBuilder) Add(command string) *BatchCommandBuilder {
	b.commands = append(b.commands, command)
	return b
}

// AddWithKey adds a command with a specific key (for OutputObject format)
func (b *BatchCommandBuilder) AddWithKey(key, command string) *BatchCommandBuilder {
	if b.outputFormat == OutputObject {
		// Wrap command to output with key
		wrapped := fmt.Sprintf("@{ '%s' = (%s) }", key, command)
		b.commands = append(b.commands, wrapped)
	} else {
		b.commands = append(b.commands, command)
	}
	return b
}

// AddConditional adds a command that only executes if condition is true
func (b *BatchCommandBuilder) AddConditional(condition, command string) *BatchCommandBuilder {
	conditional := fmt.Sprintf("if (%s) { %s }", condition, command)
	b.commands = append(b.commands, conditional)
	return b
}

// SetErrorAction sets the error action preference for all commands
func (b *BatchCommandBuilder) SetErrorAction(action string) *BatchCommandBuilder {
	b.errorAction = action
	return b
}

// SetSeparator sets the separator between commands
func (b *BatchCommandBuilder) SetSeparator(separator string) *BatchCommandBuilder {
	b.separator = separator
	return b
}

// SetOutputFormat sets how output should be formatted
func (b *BatchCommandBuilder) SetOutputFormat(format OutputFormat) *BatchCommandBuilder {
	b.outputFormat = format
	if format == OutputArray || format == OutputObject {
		b.useJSON = true
	}
	return b
}

// Build builds the final PowerShell command
func (b *BatchCommandBuilder) Build() string {
	if len(b.commands) == 0 {
		return ""
	}

	var script strings.Builder

	// Set error action preference
	script.WriteString(fmt.Sprintf("$ErrorActionPreference = '%s'\n", b.errorAction))

	if b.useJSON {
		switch b.outputFormat {
		case OutputArray:
			script.WriteString("$results = @()\n")
			for _, cmd := range b.commands {
				script.WriteString(fmt.Sprintf("$results += %s\n", cmd))
			}
			script.WriteString("$results | ConvertTo-Json -Compress -Depth 10")

		case OutputObject:
			script.WriteString("$results = @{}\n")
			for _, cmd := range b.commands {
				script.WriteString(fmt.Sprintf("%s\n", cmd))
			}
			script.WriteString("$results | ConvertTo-Json -Compress -Depth 10")

		default:
			// Just execute commands in sequence with JSON output
			script.WriteString(strings.Join(b.commands, b.separator))
		}
	} else if b.outputFormat == OutputSeparator {
		// ✨ NEW: OutputSeparator with custom separator
		const separator = "###BATCH_SEPARATOR###"
		for i, cmd := range b.commands {
			if i > 0 {
				script.WriteString(fmt.Sprintf("\nWrite-Output '%s'\n", separator))
			}
			script.WriteString(cmd)
			script.WriteString("\n")
		}
	} else {
		// Simple command concatenation
		script.WriteString(strings.Join(b.commands, b.separator))
	}

	return script.String()
}

// Count returns the number of commands in the batch
func (b *BatchCommandBuilder) Count() int {
	return len(b.commands)
}

// Clear clears all commands from the batch
func (b *BatchCommandBuilder) Clear() *BatchCommandBuilder {
	b.commands = b.commands[:0]
	return b
}

// ============================================================================
// SPECIALIZED BATCH BUILDERS
// ============================================================================

// RegistryBatchBuilder builds batches of registry operations
type RegistryBatchBuilder struct {
	*BatchCommandBuilder
}

// NewRegistryBatchBuilder creates a builder for registry operations
func NewRegistryBatchBuilder() *RegistryBatchBuilder {
	return &RegistryBatchBuilder{
		BatchCommandBuilder: NewBatchCommandBuilder().
			SetErrorAction("Stop").
			SetOutputFormat(OutputArray),
	}
}

// AddCreateValue adds a registry value creation command
func (rb *RegistryBatchBuilder) AddCreateValue(path, name, value, valueType string) *RegistryBatchBuilder {
	cmd := fmt.Sprintf(
		"New-ItemProperty -Path %s -Name %s -Value %s -PropertyType %s -Force",
		QuotePowerShellString(path),
		QuotePowerShellString(name),
		QuotePowerShellString(value),
		QuotePowerShellString(valueType),
	)
	rb.Add(cmd)
	return rb
}

// AddSetValue adds a registry value update command
func (rb *RegistryBatchBuilder) AddSetValue(path, name, value string) *RegistryBatchBuilder {
	cmd := fmt.Sprintf(
		"Set-ItemProperty -Path %s -Name %s -Value %s",
		QuotePowerShellString(path),
		QuotePowerShellString(name),
		QuotePowerShellString(value),
	)
	rb.Add(cmd)
	return rb
}

// AddGetValue adds a registry value retrieval command
func (rb *RegistryBatchBuilder) AddGetValue(path, name string) *RegistryBatchBuilder {
	cmd := fmt.Sprintf(
		"Get-ItemPropertyValue -Path %s -Name %s",
		QuotePowerShellString(path),
		QuotePowerShellString(name),
	)
	rb.Add(cmd)
	return rb
}

// AddDeleteValue adds a registry value deletion command
func (rb *RegistryBatchBuilder) AddDeleteValue(path, name string) *RegistryBatchBuilder {
	cmd := fmt.Sprintf(
		"Remove-ItemProperty -Path %s -Name %s -Force",
		QuotePowerShellString(path),
		QuotePowerShellString(name),
	)
	rb.Add(cmd)
	return rb
}

// UserBatchBuilder builds batches of user operations
type UserBatchBuilder struct {
	*BatchCommandBuilder
}

// NewUserBatchBuilder creates a builder for user operations
func NewUserBatchBuilder() *UserBatchBuilder {
	return &UserBatchBuilder{
		BatchCommandBuilder: NewBatchCommandBuilder().
			SetErrorAction("Stop").
			SetOutputFormat(OutputArray),
	}
}

// AddCreateUser adds a user creation command
func (ub *UserBatchBuilder) AddCreateUser(username, password string, options map[string]interface{}) *UserBatchBuilder {
	cmd := fmt.Sprintf(
		"New-LocalUser -Name %s -Password (ConvertTo-SecureString -AsPlainText %s -Force)",
		QuotePowerShellString(username),
		QuotePowerShellString(password),
	)

	// Add optional parameters
	if fullName, ok := options["full_name"].(string); ok {
		cmd += fmt.Sprintf(" -FullName %s", QuotePowerShellString(fullName))
	}
	if description, ok := options["description"].(string); ok {
		cmd += fmt.Sprintf(" -Description %s", QuotePowerShellString(description))
	}
	if passwordNeverExpires, ok := options["password_never_expires"].(bool); ok && passwordNeverExpires {
		cmd += " -PasswordNeverExpires"
	}

	ub.Add(cmd)
	return ub
}

// AddGetUser adds a user retrieval command
func (ub *UserBatchBuilder) AddGetUser(username string) *UserBatchBuilder {
	cmd := fmt.Sprintf(
		"Get-LocalUser -Name %s | Select-Object Name,FullName,Description,Enabled,PasswordNeverExpires",
		QuotePowerShellString(username),
	)
	ub.Add(cmd)
	return ub
}

// AddSetUserPassword adds a password change command
func (ub *UserBatchBuilder) AddSetUserPassword(username, password string) *UserBatchBuilder {
	cmd := fmt.Sprintf(
		"Set-LocalUser -Name %s -Password (ConvertTo-SecureString -AsPlainText %s -Force)",
		QuotePowerShellString(username),
		QuotePowerShellString(password),
	)
	ub.Add(cmd)
	return ub
}

// ServiceBatchBuilder builds batches of service operations
type ServiceBatchBuilder struct {
	*BatchCommandBuilder
}

// NewServiceBatchBuilder creates a builder for service operations
func NewServiceBatchBuilder() *ServiceBatchBuilder {
	return &ServiceBatchBuilder{
		BatchCommandBuilder: NewBatchCommandBuilder().
			SetErrorAction("Stop").
			SetOutputFormat(OutputArray),
	}
}

// AddGetService adds a service retrieval command
func (sb *ServiceBatchBuilder) AddGetService(serviceName string) *ServiceBatchBuilder {
	cmd := fmt.Sprintf(
		"Get-Service -Name %s | Select-Object Name,DisplayName,Status,StartType",
		QuotePowerShellString(serviceName),
	)
	sb.Add(cmd)
	return sb
}

// AddStartService adds a service start command
func (sb *ServiceBatchBuilder) AddStartService(serviceName string) *ServiceBatchBuilder {
	cmd := fmt.Sprintf(
		"Start-Service -Name %s",
		QuotePowerShellString(serviceName),
	)
	sb.Add(cmd)
	return sb
}

// AddStopService adds a service stop command
func (sb *ServiceBatchBuilder) AddStopService(serviceName string) *ServiceBatchBuilder {
	cmd := fmt.Sprintf(
		"Stop-Service -Name %s -Force",
		QuotePowerShellString(serviceName),
	)
	sb.Add(cmd)
	return sb
}

// AddSetServiceStartType adds a service startup type change command
func (sb *ServiceBatchBuilder) AddSetServiceStartType(serviceName, startType string) *ServiceBatchBuilder {
	cmd := fmt.Sprintf(
		"Set-Service -Name %s -StartupType %s",
		QuotePowerShellString(serviceName),
		QuotePowerShellString(startType),
	)
	sb.Add(cmd)
	return sb
}

// ============================================================================
// BATCH RESULT PARSER
// ============================================================================

// BatchResult represents the result of a batch operation
type BatchResult struct {
	Results []interface{}
	Errors  []error
}

// ParseBatchResult parses the output from a batch command
func ParseBatchResult(output string, format OutputFormat) (*BatchResult, error) {
	result := &BatchResult{
		Results: make([]interface{}, 0),
		Errors:  make([]error, 0),
	}

	if output == "" {
		return result, nil
	}

	switch format {
	case OutputArray:
		var results []interface{}
		if err := json.Unmarshal([]byte(output), &results); err != nil {
			return nil, fmt.Errorf("failed to parse batch results: %w", err)
		}
		result.Results = results

	case OutputObject:
		var results map[string]interface{}
		if err := json.Unmarshal([]byte(output), &results); err != nil {
			return nil, fmt.Errorf("failed to parse batch results: %w", err)
		}
		for _, v := range results {
			result.Results = append(result.Results, v)
		}

	case OutputRaw:
		lines := strings.Split(strings.TrimSpace(output), "\n")
		for _, line := range lines {
			if line != "" {
				result.Results = append(result.Results, line)
			}
		}

	case OutputSeparator:
		// ✨ NEW: Split by custom separator
		const separator = "###BATCH_SEPARATOR###"
		parts := strings.Split(output, separator)
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			result.Results = append(result.Results, trimmed)
		}

	default:
		result.Results = append(result.Results, output)
	}

	return result, nil
}

// GetResult retrieves a specific result by index
func (br *BatchResult) GetResult(index int) (interface{}, error) {
	if index < 0 || index >= len(br.Results) {
		return nil, fmt.Errorf("index %d out of range (0-%d)", index, len(br.Results)-1)
	}
	return br.Results[index], nil
}

// GetStringResult retrieves a result as a string
func (br *BatchResult) GetStringResult(index int) (string, error) {
	result, err := br.GetResult(index)
	if err != nil {
		return "", err
	}

	switch v := result.(type) {
	case string:
		return v, nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}

// HasErrors checks if any errors occurred
func (br *BatchResult) HasErrors() bool {
	return len(br.Errors) > 0
}

// Count returns the number of results
func (br *BatchResult) Count() int {
	return len(br.Results)
}
