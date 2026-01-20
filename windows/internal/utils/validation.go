package utils

import (
	"fmt"

	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
)

// ValidationError represents a validation error with context
type ValidationError struct {
	Field      string
	Value      string
	ResourceID string
	Err        error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s' in resource '%s': %v",
		e.Field, e.ResourceID, e.Err)
}

// Unwrap returns the underlying error
func (e *ValidationError) Unwrap() error {
	return e.Err
}

// ValidateField validates a single field value and returns a properly formatted error
// if validation fails.
//
// Parameters:
//   - value: The value to validate
//   - resourceID: The ID of the resource being validated (for error context)
//   - fieldName: The name of the field being validated (for error context)
//
// Returns:
//   - error: A formatted error if validation fails, nil otherwise
//
// Example:
//
//	if err := utils.ValidateField(username, "user_123", "username"); err != nil {
//	    return err
//	}
func ValidateField(value, resourceID, fieldName string) error {
	if err := powershell.ValidatePowerShellArgument(value); err != nil {
		return HandleResourceError("validate", resourceID, fieldName, err)
	}
	return nil
}

// ValidateFields validates multiple fields at once and returns the first error encountered.
// This is useful when you need to validate several fields before proceeding.
//
// Parameters:
//   - resourceID: The ID of the resource being validated
//   - fields: A map of field names to their values
//
// Returns:
//   - error: The first validation error encountered, or nil if all fields are valid
//
// Example:
//
//	err := utils.ValidateFields("service_123", map[string]string{
//	    "name": serviceName,
//	    "display_name": displayName,
//	    "description": description,
//	})
//	if err != nil {
//	    return err
//	}
func ValidateFields(resourceID string, fields map[string]string) error {
	for fieldName, value := range fields {
		if err := ValidateField(value, resourceID, fieldName); err != nil {
			return err
		}
	}
	return nil
}

// ValidateOptionalField validates a field only if it has a value.
// This is useful for optional schema fields.
//
// Parameters:
//   - value: The value to validate (can be empty)
//   - resourceID: The ID of the resource being validated
//   - fieldName: The name of the field being validated
//
// Returns:
//   - error: A formatted error if validation fails, nil if empty or valid
//
// Example:
//
//	if err := utils.ValidateOptionalField(description, "user_123", "description"); err != nil {
//	    return err
//	}
func ValidateOptionalField(value, resourceID, fieldName string) error {
	if value == "" {
		return nil
	}
	return ValidateField(value, resourceID, fieldName)
}

// ValidateSchemaString validates a string field from Terraform schema data.
// It handles the type assertion and validation in one call.
//
// Parameters:
//   - d: The schema.ResourceData object
//   - key: The schema key to validate
//   - resourceID: The ID of the resource being validated
//
// Returns:
//   - string: The validated value
//   - error: A formatted error if validation fails
//
// Example:
//
//	username, err := utils.ValidateSchemaString(d, "username", d.Id())
//	if err != nil {
//	    return err
//	}
func ValidateSchemaString(d interface{}, key, resourceID string) (string, error) {
	// Type assertion helper
	type getter interface {
		Get(string) interface{}
	}

	g, ok := d.(getter)
	if !ok {
		return "", fmt.Errorf("invalid data type for schema validation")
	}

	value, ok := g.Get(key).(string)
	if !ok {
		return "", HandleResourceError("validate", resourceID, key,
			fmt.Errorf("field is not a string"))
	}

	if err := ValidateField(value, resourceID, key); err != nil {
		return "", err
	}

	return value, nil
}

// ValidateSchemaOptionalString validates an optional string field from Terraform schema.
// Returns empty string and nil error if field is not set.
//
// Parameters:
//   - d: The schema.ResourceData object
//   - key: The schema key to validate
//   - resourceID: The ID of the resource being validated
//
// Returns:
//   - string: The validated value (empty if not set)
//   - bool: Whether the field was set
//   - error: A formatted error if validation fails
//
// Example:
//
//	description, ok, err := utils.ValidateSchemaOptionalString(d, "description", d.Id())
//	if err != nil {
//	    return err
//	}
//	if ok {
//	    // Use description
//	}
func ValidateSchemaOptionalString(d interface{}, key, resourceID string) (string, bool, error) {
	type getterWithOk interface {
		GetOk(string) (interface{}, bool)
	}

	g, ok := d.(getterWithOk)
	if !ok {
		return "", false, fmt.Errorf("invalid data type for schema validation")
	}

	val, exists := g.GetOk(key)
	if !exists {
		return "", false, nil
	}

	value, ok := val.(string)
	if !ok {
		return "", true, HandleResourceError("validate", resourceID, key,
			fmt.Errorf("field is not a string"))
	}

	if err := ValidateOptionalField(value, resourceID, key); err != nil {
		return "", true, err
	}

	return value, true, nil
}

// FieldValidator is a chainable validator for multiple fields
type FieldValidator struct {
	resourceID string
	errors     []error
}

// NewFieldValidator creates a new chainable field validator
//
// Example:
//
//	validator := utils.NewFieldValidator("user_123")
//	err := validator.
//	    Validate("username", username).
//	    Validate("full_name", fullName).
//	    ValidateOptional("description", description).
//	    Error()
func NewFieldValidator(resourceID string) *FieldValidator {
	return &FieldValidator{
		resourceID: resourceID,
		errors:     make([]error, 0),
	}
}

// Validate adds a required field validation to the chain
func (fv *FieldValidator) Validate(fieldName, value string) *FieldValidator {
	if err := ValidateField(value, fv.resourceID, fieldName); err != nil {
		fv.errors = append(fv.errors, err)
	}
	return fv
}

// ValidateOptional adds an optional field validation to the chain
func (fv *FieldValidator) ValidateOptional(fieldName, value string) *FieldValidator {
	if err := ValidateOptionalField(value, fv.resourceID, fieldName); err != nil {
		fv.errors = append(fv.errors, err)
	}
	return fv
}

// ValidateFields adds multiple field validations to the chain
func (fv *FieldValidator) ValidateFields(fields map[string]string) *FieldValidator {
	if err := ValidateFields(fv.resourceID, fields); err != nil {
		fv.errors = append(fv.errors, err)
	}
	return fv
}

// Error returns the first error encountered, or nil if all validations passed
func (fv *FieldValidator) Error() error {
	if len(fv.errors) > 0 {
		return fv.errors[0]
	}
	return nil
}

// Errors returns all validation errors encountered
func (fv *FieldValidator) Errors() []error {
	return fv.errors
}

// HasErrors returns true if any validation failed
func (fv *FieldValidator) HasErrors() bool {
	return len(fv.errors) > 0
}
