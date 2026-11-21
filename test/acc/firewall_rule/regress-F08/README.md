# Regression F08 — plan non vide apres import (orthographes non canoniques)

## Contexte

Finding F08 (run `2611210818`, scenario `06-import-canonical-plan-empty`,
tentative 1) : apres `apply` d'une regle aux orthographes hostiles puis
reset du state par lab-runner (`rm terraform.tfstate*`, objet conserve sur
203, pratique du cycle 1), `import` sort en exit 0 mais les deux plans
suivants sortent en `detailed_exit 2` au lieu de 0 :

- `~ protocol = "UDP" -> "udp"` ;
- `~ local_port = ["55271", "55272"] -> ["55272", "55271-55271", "55271"]`
  (plage degeneree + doublon + desordre) ;
- `~ remote_address` reordonne (adresses non triees).

Reproduit a l'identique avec la config minimale `repro/F08` (run
`2611210818`, binaire du run, LAB 201 -> 203) : apply exit 0, import exit 0,
plans post-import exit 2 (x2, diffs identiques), destroy exit 0,
`REMAINING:0` verifie sur 203.

## Cause (sans modification de code — piste pour `provider-coder`)

- `ImportState`
  (`internal/provider/resource_windows_firewall_rule.go`, lignes ~648-704)
  stocke l'etat canonique relu de Windows via `firewallStateToModel`
  (`UDP`, `[55271,55272]`, adresses triees) — prouve par
  `repro/F08/logs/F08-6-postimport-show.log`.
- Sur le chemin normal, l'etat garde au contraire l'orthographe config
  (prouve : `F08-4-postapply-show.log` = `udp`, liste brute, non triee),
  car `terraform-plugin-framework` v1.19.0 n'execute `SchemaSemanticEquality`
  que sur les reponses Create/Update (`server_createresource.go:199`,
  `server_updateresource.go:229`) et Read/refresh
  (`server_readresource.go:228`) — **jamais dans `PlanResourceChange`**
  (verifie : aucune reference SemanticEquality dans
  `server_planresourcechange.go`). Les plans des scenarios 01/03/04 sont
  donc trivialement vides (verbatim-verbatim) sans jamais exercer le
  folding.
- Apres import, le plan compare config-verbatim vs etat-canonique sans
  passe d'egalite semantique : `firewallProtocolValue.StringSemanticEquals`
  (~1285) et `firewallCanonicalListValue.ListSemanticEquals` (~1407) ne
  sont tout simplement pas appeles sur ce chemin.

Correction suggeree : **ne PAS** reintroduire un plan modifier
canonicalisant config -> canonique (tente en F01/F02/F03 attempt 2, rejete
`Provider produced invalid plan` par Terraform core). Replier le **plan
vers le prior** quand semantiquement egal : `ModifyPlan` de la resource
(ou plan modifier par attribut lisant le prior state) qui, pour
`protocol`/`local_port`/`remote_port`/`local_address`/`remote_address`,
recopie la valeur du prior si la comparaison canonique
(`CanonicalFirewallProtocol`, `firewallCanonicalListStringsEqual`) la
declare egale au planifie. Copier le prior est toujours legal cote core
(planifie == prior = no-op), corrige le chemin import (planifie devient
canonique-prior -> vide), ne change rien au chemin normal et laisse les
vrais changements visibles. Valider contre le mode de rejet invalid-plan
de l'attempt 2 F01/F02/F03.

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE`
pointe sur le `terraform.rc` du run (dev_override vers le binaire provider
du run), en suivant la procedure `acc/lab-runner`.
Le prefixe est parametrable via `-var rule_prefix=...` (defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu :
   exit 0 (1 added). Sur 203 : regle `<prefix>-regress-f08` en UDP,
   `LocalPort {55311,55312}`.
3. `terraform plan -detailed-exitcode -input=false -no-color` — attendu :
   exit 0 (`No changes`, diag post-apply).
4. Reset du state **sans toucher a 203** (pratique lab-runner du cycle 1) :
   `Remove-Item terraform.tfstate* -Force` dans le dossier du scenario.
5. `terraform import -input=false -no-color windows_firewall_rule.main <prefix>-regress-f08`
   — attendu : exit 0 (`Import successful!`).
6. `terraform plan -detailed-exitcode -input=false -no-color` — attendu
   **apres correction : exit 0** (`No changes`). Avant correction :
   exit 2 (diffs `protocol`, `local_port`, `remote_address`).
7. Repeter l'etape 6 — attendu : exit 0 les deux fois.
8. `terraform destroy -auto-approve -input=false -no-color` — attendu : exit 0.
9. Verification sur 203 :
   `Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -like '<prefix>-regress-f08*' }`
   ne renvoie aucune ligne (aucun residu).

## Attendu

- Apply puis import puis double plan vide avec des orthographes
  volontairement non canoniques (`udp`, `55311-55311`, listes non triees).
- Aucun secret dans ce scenario, aucun fichier d'etat versionne.
