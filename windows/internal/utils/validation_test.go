package utils

import (
	"strings"
	"testing"
)

func TestValidateField(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		resourceID  string
		fieldName   string
		expectError bool
	}{
		{
			name:        "valid simple string",
			value:       "testuser",
			resourceID:  "user_123",
			fieldName:   "username",
			expectError: false,
		},
		{
			name:        "valid string with spaces",
			value:       "Test User",
			resourceID:  "user_123",
			fieldName:   "full_name",
			expectError: false,
		},
		{
			name:        "string with pipe character",
			value:       "test|user",
			resourceID:  "user_123",
			fieldName:   "username",
			expectError: true,
		},
		{
			name:        "string with semicolon",
			value:       "test;user",
			resourceID:  "user_123",
			fieldName:   "username",
			expectError: true,
		},
		{
			name:        "string with command substitution",
			value:       "$(whoami)",
			resourceID:  "user_123",
			fieldName:   "username",
			expectError: true,
		},
		{
			name:        "empty string",
			value:       "",
			resourceID:  "user_123",
			fieldName:   "username",
			expectError: false, // Empty strings are allowed, validation happens in PowerShell
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateField(tt.value, tt.resourceID, tt.fieldName)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check error message format if error expected
			if tt.expectError && err != nil {
				errMsg := err.Error()
				if !strings.Contains(errMsg, tt.resourceID) {
					t.Errorf("error message should contain resource ID %s: %v", tt.resourceID, errMsg)
				}
				if !strings.Contains(errMsg, tt.fieldName) {
					t.Errorf("error message should contain field name %s: %v", tt.fieldName, errMsg)
				}
			}
		})
	}
}

func TestValidateFields(t *testing.T) {
	tests := []struct {
		name        string
		resourceID  string
		fields      map[string]string
		expectError bool
	}{
		{
			name:       "all valid fields",
			resourceID: "service_123",
			fields: map[string]string{
				"name":         "MyService",
				"display_name": "My Service Display",
				"description":  "Service description",
			},
			expectError: false,
		},
		{
			name:       "one invalid field",
			resourceID: "service_123",
			fields: map[string]string{
				"name":         "MyService",
				"display_name": "Display|Name", // Invalid
				"description":  "Service description",
			},
			expectError: true,
		},
		{
			name:        "empty fields map",
			resourceID:  "service_123",
			fields:      map[string]string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFields(tt.resourceID, tt.fields)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateOptionalField(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		resourceID  string
		fieldName   string
		expectError bool
	}{
		{
			name:        "empty value should pass",
			value:       "",
			resourceID:  "user_123",
			fieldName:   "description",
			expectError: false,
		},
		{
			name:        "valid value should pass",
			value:       "Test description",
			resourceID:  "user_123",
			fieldName:   "description",
			expectError: false,
		},
		{
			name:        "invalid value should fail",
			value:       "Test|description",
			resourceID:  "user_123",
			fieldName:   "description",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOptionalField(tt.value, tt.resourceID, tt.fieldName)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestFieldValidator(t *testing.T) {
	t.Run("chain validation - all valid", func(t *testing.T) {
		validator := NewFieldValidator("user_123")
		err := validator.
			Validate("username", "testuser").
			Validate("full_name", "Test User").
			ValidateOptional("description", "User description").
			Error()

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if validator.HasErrors() {
			t.Error("validator should not have errors")
		}
	})

	t.Run("chain validation - one invalid", func(t *testing.T) {
		validator := NewFieldValidator("user_123")
		err := validator.
			Validate("username", "testuser").
			Validate("full_name", "Test|User"). // Invalid
			ValidateOptional("description", "User description").
			Error()

		if err == nil {
			t.Error("expected error but got nil")
		}

		if !validator.HasErrors() {
			t.Error("validator should have errors")
		}
	})

	t.Run("chain validation - multiple invalids", func(t *testing.T) {
		validator := NewFieldValidator("user_123")
		validator.
			Validate("username", "test|user").      // Invalid
			Validate("full_name", "Test;User").     // Invalid
			ValidateOptional("description", "Desc") // Valid

		errors := validator.Errors()
		if len(errors) != 2 {
			t.Errorf("expected 2 errors, got %d", len(errors))
		}
	})
}
