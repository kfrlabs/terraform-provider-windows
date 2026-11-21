# Regression F14 — CV-3 : `Any` ne doit pas etre melange (negatif)

## Contexte

Scenario `10-negative-address-any-mix` du run `2611210928` (tentative 1) :
`local_address = ["Any", "10.0.0.0/8"]` et `remote_address = ["any", ...]`
passaient `validate` (exit 0) et `plan` (exit 0, `Plan: 2 to add`) au lieu
d'echouer avec `Invalid address combination`.

Enquete (triage F14) : le plan du run utilisait par erreur l'ancien binaire
partage `C:\lab\terraform-windows-test\terraform-provider-windows.exe`
(34226688 octets, 17/11/2026 — dev_override racine au lieu du binaire du run
`...\2611210928\bin`, 34354176 octets). Rejoue avec le binaire du run
(config minimale `work/acc/firewall_rule/2611210928/repro/F14`) :
`validate` exit 1 et `plan` exit 1 avec `Invalid address combination` sur les
deux ressources (casse exacte `Any` comme minuscule `any`, `local` comme
`remote`), destroy exit 0, residus 0 sur 203. Le validateur
`firewallRuleAddressAnyValidator`
(`internal/provider/resource_windows_firewall_rule.go`, lignes ~1283-1340)
fonctionne : l'echec du run est un artefact de harness (`infra_error`),
pas un bug provider.

Ce scenario negatif fige le comportement : sans CV-3, Windows ignore
silencieusement le `Any` combine (F03), la config ne prendrait jamais effet.

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE`
pointe sur le `terraform.rc` du run (dev_override vers le binaire provider
du run — ne pas utiliser le binaire partage racine), en suivant la procedure
`acc/lab-runner`. Le prefixe est parametrable via `-var rule_prefix=...`
(defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform validate -no-color` — attendu : exit 1,
   `/Invalid address combination/` (deux diagnostics, `any_local` +
   `any_remote`).
3. `terraform plan -input=false -no-color` — attendu : exit 1, meme motif.
4. Verification sur 203 : aucune regle `<prefix>-regress-f14-*` (rien
   n'est cree, le rejet est plan-time).
5. `terraform destroy -auto-approve -input=false -no-color` — attendu :
   exit 0 (no-op ; echoue aussi au validate si l'etat est vide — par design
   du scenario negatif, comme le run : ne pas confondre avec un echec).

## Attendu

- `validate` et `plan` rejettent le melange `Any` + adresses concretes.
- Aucun secret dans ce scenario, aucun fichier d'etat versionne.
