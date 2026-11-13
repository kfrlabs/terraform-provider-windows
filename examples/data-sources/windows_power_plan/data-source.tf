terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host     = var.windows_host
  username = var.windows_username
  password = var.windows_password
}

# Singleton — no lookup keys required.
data "windows_power_plan" "current" {}

output "plan_guid" {
  value = data.windows_power_plan.current.plan_guid
}

output "plan_name" {
  value = data.windows_power_plan.current.plan_name
}

output "plans" {
  value = data.windows_power_plan.current.plans
}

output "id" {
  value = data.windows_power_plan.current.id
}
