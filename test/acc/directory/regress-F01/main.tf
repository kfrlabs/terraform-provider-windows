# Regression scenario for F01 (contrat B+): a non-canonical `attributes`
# spelling (duplicates, scrambled order) must be REJECTED AT PLAN with an
# explicit diagnostic ("must be unique and in canonical order:
# hidden, readonly, system") instead of failing with
# "Provider produced inconsistent result after apply" (attempt 2) or
# "Provider produced invalid plan" (attempt 3, planmodifier).
variable "name_prefix" {
  type    = string
  default = "tfacc-f01"
}

resource "windows_directory" "dedup" {
  path = "C:\\Windows\\Temp\\${var.name_prefix}-dedup"
  attributes = [
    "system", "hidden",
    "system", "readonly",
    "hidden", "system",
  ]
}
