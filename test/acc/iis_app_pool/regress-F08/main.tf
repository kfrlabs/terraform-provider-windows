# Regression F08 : pools paralleles, "Object reference not set" (IIS).
# Trois pools independantes (aucune dependance), noms simples, attributs
# minimaux. Terraform les cree/detruit en parallele (parallelisme par
# defaut) : avant correction, ~1 operation sur 3 echoue par intermittence
# avec "Object reference not set to an instance of an object" (kind
# unknown), sur create comme sur delete. La reprise serielle
# (-parallelism=1) reussit toujours : l'echec vient d'une course d'ecriture
# concurrente sur applicationHost.config, pas du quoting (les noms sont
# simples ici) ni d'un etat invalide.
variable "pool_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_iis_app_pool" "a" {
  name = "${var.pool_prefix}-regress-f08a"
}

resource "windows_iis_app_pool" "b" {
  name = "${var.pool_prefix}-regress-f08b"
}

resource "windows_iis_app_pool" "c" {
  name = "${var.pool_prefix}-regress-f08c"
}
