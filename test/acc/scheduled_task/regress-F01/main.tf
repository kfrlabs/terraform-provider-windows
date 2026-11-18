# Regression F01 : l'import d'une tache SYSTEM/ServiceAccount doit renseigner
# principal.logon_type dans l'etat, sinon le plan post-import affiche
# `+ logon_type = "ServiceAccount"` alors que la configuration est deja a
# l'identique du reel.
variable "task_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_scheduled_task" "repro" {
  name = "${var.task_prefix}-regress-f01"
  path = "\\${var.task_prefix}-regress-f01\\"

  principal = {
    user_id    = "SYSTEM"
    logon_type = "ServiceAccount"
    run_level  = "Limited"
  }

  actions = [{
    execute = "C:\\Windows\\System32\\cmd.exe"
  }]

  triggers = [{
    type = "AtStartup"
  }]
}
