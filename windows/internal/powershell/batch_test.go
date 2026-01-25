package powershell

import (
	"fmt"
	"strings"
	"testing"
)

func TestBatchCommandBuilderBasic(t *testing.T) {
	builder := NewBatchCommandBuilder()

	builder.Add("Get-Process").
		Add("Get-Service").
		Add("Get-LocalUser")

	result := builder.Build()

	if !strings.Contains(result, "Get-Process") {
		t.Error("Result should contain Get-Process")
	}
	if !strings.Contains(result, "Get-Service") {
		t.Error("Result should contain Get-Service")
	}
	if !strings.Contains(result, "Get-LocalUser") {
		t.Error("Result should contain Get-LocalUser")
	}

	if builder.Count() != 3 {
		t.Errorf("Expected 3 commands, got %d", builder.Count())
	}
}

func TestBatchCommandBuilderJSON(t *testing.T) {
	builder := NewJSONBatchCommandBuilder()

	builder.Add("Get-Service | Select-Object Name,Status").
		Add("Get-Process | Select-Object Name,Id")

	result := builder.Build()

	if !strings.Contains(result, "$results = @()") {
		t.Error("Result should initialize array for JSON output")
	}
	if !strings.Contains(result, "ConvertTo-Json") {
		t.Error("Result should contain ConvertTo-Json")
	}
}

func TestBatchCommandBuilderConditional(t *testing.T) {
	builder := NewBatchCommandBuilder()

	builder.AddConditional("$true", "Write-Host 'Condition met'")

	result := builder.Build()

	if !strings.Contains(result, "if ($true)") {
		t.Error("Result should contain conditional statement")
	}
}

func TestBatchCommandBuilderClear(t *testing.T) {
	builder := NewBatchCommandBuilder()

	builder.Add("Command1").Add("Command2").Add("Command3")

	if builder.Count() != 3 {
		t.Errorf("Expected 3 commands before clear, got %d", builder.Count())
	}

	builder.Clear()

	if builder.Count() != 0 {
		t.Errorf("Expected 0 commands after clear, got %d", builder.Count())
	}
}

func TestBatchCommandBuilderSeparator(t *testing.T) {
	builder := NewBatchCommandBuilder()

	builder.SetSeparator(" | ").
		Add("Get-Process").
		Add("Where-Object {$_.CPU -gt 10}").
		Add("Select-Object Name,CPU")

	result := builder.Build()

	// Check that custom separator is used
	if !strings.Contains(result, "Get-Process | Where-Object") {
		t.Error("Result should use custom separator")
	}
}

func TestBatchCommandBuilderErrorAction(t *testing.T) {
	builder := NewBatchCommandBuilder()

	builder.SetErrorAction("Continue").
		Add("Get-Service")

	result := builder.Build()

	if !strings.Contains(result, "$ErrorActionPreference = 'Continue'") {
		t.Error("Result should set custom error action")
	}
}

func TestRegistryBatchBuilder(t *testing.T) {
	builder := NewRegistryBatchBuilder()

	builder.AddCreateValue("HKLM:\\Software\\Test", "Value1", "Data1", "String").
		AddCreateValue("HKLM:\\Software\\Test", "Value2", "123", "DWord").
		AddGetValue("HKLM:\\Software\\Test", "Value1")

	result := builder.Build()

	if !strings.Contains(result, "New-ItemProperty") {
		t.Error("Result should contain New-ItemProperty")
	}
	if !strings.Contains(result, "Get-ItemPropertyValue") {
		t.Error("Result should contain Get-ItemPropertyValue")
	}
	if builder.Count() != 3 {
		t.Errorf("Expected 3 commands, got %d", builder.Count())
	}
}

func TestRegistryBatchBuilderSetValue(t *testing.T) {
	builder := NewRegistryBatchBuilder()

	builder.AddSetValue("HKLM:\\Software\\Test", "Value1", "NewData")

	result := builder.Build()

	if !strings.Contains(result, "Set-ItemProperty") {
		t.Error("Result should contain Set-ItemProperty")
	}
}

func TestRegistryBatchBuilderDeleteValue(t *testing.T) {
	builder := NewRegistryBatchBuilder()

	builder.AddDeleteValue("HKLM:\\Software\\Test", "Value1")

	result := builder.Build()

	if !strings.Contains(result, "Remove-ItemProperty") {
		t.Error("Result should contain Remove-ItemProperty")
	}
}

func TestUserBatchBuilder(t *testing.T) {
	builder := NewUserBatchBuilder()

	options := map[string]interface{}{
		"full_name":              "Test User",
		"description":            "Test account",
		"password_never_expires": true,
	}

	builder.AddCreateUser("testuser", "P@ssw0rd!", options).
		AddGetUser("testuser")

	result := builder.Build()

	if !strings.Contains(result, "New-LocalUser") {
		t.Error("Result should contain New-LocalUser")
	}
	if !strings.Contains(result, "Get-LocalUser") {
		t.Error("Result should contain Get-LocalUser")
	}
	if !strings.Contains(result, "-FullName") {
		t.Error("Result should include FullName parameter")
	}
	if !strings.Contains(result, "-PasswordNeverExpires") {
		t.Error("Result should include PasswordNeverExpires parameter")
	}
}

func TestUserBatchBuilderSetPassword(t *testing.T) {
	builder := NewUserBatchBuilder()

	builder.AddSetUserPassword("testuser", "NewP@ssw0rd!")

	result := builder.Build()

	if !strings.Contains(result, "Set-LocalUser") {
		t.Error("Result should contain Set-LocalUser")
	}
	if !strings.Contains(result, "ConvertTo-SecureString") {
		t.Error("Result should contain ConvertTo-SecureString")
	}
}

func TestServiceBatchBuilder(t *testing.T) {
	builder := NewServiceBatchBuilder()

	builder.AddGetService("W3SVC").
		AddStartService("W3SVC").
		AddSetServiceStartType("W3SVC", "Automatic")

	result := builder.Build()

	if !strings.Contains(result, "Get-Service") {
		t.Error("Result should contain Get-Service")
	}
	if !strings.Contains(result, "Start-Service") {
		t.Error("Result should contain Start-Service")
	}
	if !strings.Contains(result, "Set-Service") {
		t.Error("Result should contain Set-Service")
	}
	if builder.Count() != 3 {
		t.Errorf("Expected 3 commands, got %d", builder.Count())
	}
}

func TestServiceBatchBuilderStopService(t *testing.T) {
	builder := NewServiceBatchBuilder()

	builder.AddStopService("W3SVC")

	result := builder.Build()

	if !strings.Contains(result, "Stop-Service") {
		t.Error("Result should contain Stop-Service")
	}
	if !strings.Contains(result, "-Force") {
		t.Error("Result should include -Force parameter")
	}
}

func TestParseBatchResultArray(t *testing.T) {
	jsonOutput := `["result1", "result2", "result3"]`

	result, err := ParseBatchResult(jsonOutput, OutputArray)
	if err != nil {
		t.Fatalf("Failed to parse batch result: %v", err)
	}

	if result.Count() != 3 {
		t.Errorf("Expected 3 results, got %d", result.Count())
	}

	str, err := result.GetStringResult(0)
	if err != nil {
		t.Fatalf("Failed to get string result: %v", err)
	}
	if str != "result1" {
		t.Errorf("Expected 'result1', got '%s'", str)
	}
}

func TestParseBatchResultObject(t *testing.T) {
	jsonOutput := `{"key1": "value1", "key2": "value2"}`

	result, err := ParseBatchResult(jsonOutput, OutputObject)
	if err != nil {
		t.Fatalf("Failed to parse batch result: %v", err)
	}

	if result.Count() != 2 {
		t.Errorf("Expected 2 results, got %d", result.Count())
	}
}

func TestParseBatchResultRaw(t *testing.T) {
	rawOutput := "line1\nline2\nline3"

	result, err := ParseBatchResult(rawOutput, OutputRaw)
	if err != nil {
		t.Fatalf("Failed to parse batch result: %v", err)
	}

	if result.Count() != 3 {
		t.Errorf("Expected 3 results, got %d", result.Count())
	}

	str, err := result.GetStringResult(1)
	if err != nil {
		t.Fatalf("Failed to get string result: %v", err)
	}
	if str != "line2" {
		t.Errorf("Expected 'line2', got '%s'", str)
	}
}

func TestParseBatchResultEmpty(t *testing.T) {
	result, err := ParseBatchResult("", OutputArray)
	if err != nil {
		t.Fatalf("Failed to parse empty result: %v", err)
	}

	if result.Count() != 0 {
		t.Errorf("Expected 0 results for empty input, got %d", result.Count())
	}
}

func TestBatchResultGetResultOutOfRange(t *testing.T) {
	jsonOutput := `["result1"]`

	result, err := ParseBatchResult(jsonOutput, OutputArray)
	if err != nil {
		t.Fatalf("Failed to parse batch result: %v", err)
	}

	_, err = result.GetResult(5)
	if err == nil {
		t.Error("Expected error for out of range index")
	}
}

func TestBatchResultHasErrors(t *testing.T) {
	result := &BatchResult{
		Results: []interface{}{"result1"},
		Errors:  []error{},
	}

	if result.HasErrors() {
		t.Error("Expected no errors")
	}

	result.Errors = append(result.Errors, fmt.Errorf("test error"))

	if !result.HasErrors() {
		t.Error("Expected errors to be present")
	}
}

func TestComplexJSONParsing(t *testing.T) {
	// Simulate PowerShell output with complex objects
	jsonOutput := `[
		{"Name": "Service1", "Status": "Running", "StartType": "Automatic"},
		{"Name": "Service2", "Status": "Stopped", "StartType": "Manual"}
	]`

	result, err := ParseBatchResult(jsonOutput, OutputArray)
	if err != nil {
		t.Fatalf("Failed to parse complex JSON: %v", err)
	}

	if result.Count() != 2 {
		t.Errorf("Expected 2 results, got %d", result.Count())
	}

	// Verify we can access nested properties
	firstResult := result.Results[0]
	objMap, ok := firstResult.(map[string]interface{})
	if !ok {
		t.Fatal("Expected result to be a map")
	}

	if objMap["Name"] != "Service1" {
		t.Errorf("Expected Name='Service1', got '%v'", objMap["Name"])
	}
}

func TestBatchCommandWithQuoting(t *testing.T) {
	builder := NewRegistryBatchBuilder()

	// Test with values that need proper quoting
	builder.AddCreateValue("HKLM:\\Software\\Test", "Value'With'Quotes", "Data", "String")

	result := builder.Build()

	// Should properly escape the single quote
	if !strings.Contains(result, "''") {
		t.Error("Result should properly escape single quotes")
	}
}

func TestOutputFormatNone(t *testing.T) {
	builder := NewBatchCommandBuilder()
	builder.SetOutputFormat(OutputNone)

	builder.Add("Get-Service").Add("Get-Process")

	result := builder.Build()

	// Should not have JSON conversion
	if strings.Contains(result, "ConvertTo-Json") {
		t.Error("OutputNone should not include JSON conversion")
	}
}

func BenchmarkBatchCommandBuilder(b *testing.B) {
	for i := 0; i < b.N; i++ {
		builder := NewBatchCommandBuilder()
		for j := 0; j < 100; j++ {
			builder.Add(fmt.Sprintf("Get-Process -Id %d", j))
		}
		_ = builder.Build()
	}
}

func BenchmarkRegistryBatchBuilder(b *testing.B) {
	for i := 0; i < b.N; i++ {
		builder := NewRegistryBatchBuilder()
		for j := 0; j < 50; j++ {
			builder.AddCreateValue(
				"HKLM:\\Software\\Test",
				fmt.Sprintf("Value%d", j),
				fmt.Sprintf("Data%d", j),
				"String",
			)
		}
		_ = builder.Build()
	}
}
