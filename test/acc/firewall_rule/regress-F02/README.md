# Regression F02 — Windows canonicalise le protocole (casse + numerique)

## Contexte

Finding F02 (run `2611210137`, scenario `02-inputs-protocol-keywords`,
tentative 1) : trois regles valides plan-time echouent au Create, chacune
avec `inconsistent result after apply` car Windows renvoie la forme
canonicalisee du protocole :

- `protocol = "ANY"` -> `.protocol: was "ANY", but now "Any"` ;
- `protocol = "tcp"` -> `.protocol: was "tcp", but now "TCP"` ;
- `protocol = "1"` -> `.protocol: was "1", but now "ICMPv4"`.

Les 3 regles existaient sur 203 avec les valeurs normalisees
(`Any`/`TCP`/`ICMPv4`) — orphelines nettoyees via `Remove-NetFirewallRule`.

Reproduit a l'identique avec la config minimale `repro/F02` (run
`2611210137`) : apply exit 1, les 3 messages, regles
`tfacc-2611210137-rf02-{lower,num,any}` creees sur 203 puis nettoyees
(`REMAINING:0` verifie sur 203).

## Cause (sans modification de code — piste pour `provider-coder`)

- `firewallProtocolValidator` (`internal/provider/resource_windows_firewall_rule.go`,
  lignes ~987-1013) accepte insensible a la casse (`EqualFold`) plus les
  numeriques `0-255`, sans canonicaliser.
- `modelToFirewallInput` (lignes ~677-720) puis `buildFirewallParams`
  (`internal/winclient/firewall_rule.go`, lignes ~323-326 : `Protocol = ...`
  valeur brute) transmettent la casse/forme d'origine a
  `New-NetFirewallRule`.
- Le `Read` (`frReadBody`, lignes ~128-130 : `$proto = [string]$pf.Protocol`)
  renvoie la forme canonicalisee Windows, stockee telle quelle par
  `firewallStateToModel` (lignes ~758-788) — d'ou le mismatch plan/etat.

Correction suggeree : canonicaliser plan-side dans `modelToFirewallInput`
(ou via `firewallProtocolValidator` + plan modifier) — replier la casse
vers le mot-cle canonique (`TCP`, `UDP`, `ICMPv4`, `ICMPv6`, `IGMP`, `Any`)
et mapper les numeriques connus vers leur mot-cle (`1` -> `ICMPv4`, etc.,
a valider contre `Get-NetFirewallPortFilter` sur 203 pour chaque valeur).
Ne pas normaliser uniquement au `Read` : le mismatch plan/etat casserait
quand meme le Create (`inconsistent result` compare plan vs nouvel etat).

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE`
pointe sur le `terraform.rc` du run (dev_override vers le binaire provider
du run), en suivant la procedure `acc/lab-runner`.
Le prefixe est parametrable via `-var rule_prefix=...` (defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu
   **apres correction : exit 0** (3 added). Avant correction : exit 1
   (3x `inconsistent result after apply` sur `.protocol`).
3. `terraform plan -detailed-exitcode -input=false -no-color` — attendu :
   exit 0 (`No changes`).
4. Verification sur 203 :
   `Get-NetFirewallRule -Name '<prefix>-regress-f02-*' | Get-NetFirewallPortFilter`
   montre `TCP`, `ICMPv4`, `Any`.
5. `terraform destroy -auto-approve -input=false -no-color` — attendu : exit 0.
6. Verification sur 203 : aucune regle `<prefix>-regress-f02-*`, aucun residu.

## Attendu

- Apply puis plan vide avec les trois formes d'entree (`tcp`, `1`, `ANY`).
- Aucun secret dans ce scenario, aucun fichier d'etat versionne.
