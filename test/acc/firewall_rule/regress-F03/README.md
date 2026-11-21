# Regression F03 — ordre des adresses + `any` combine (normalisation Windows)

## Contexte

Finding F03 (run `2611210137`, scenario `03-inputs-address-variants`,
tentative 1) : `local_address = ["192.168.10.11", "10.0.0.0/8", ...]` et
`remote_address = ["any", "203.0.113.7", "198.51.100.0/24"]` echouent au
Create avec 4x `inconsistent result after apply` :

- `.local_address[0]: was "192.168.10.11", but now "10.0.0.0/8"` (et
  `[1]` inverse) — **Windows reordonne les listes** ;
- `.remote_address[0]: was "any", but now "198.51.100.0/24"` +
  `element 2 has vanished` — **Windows supprime `any` combine a des
  adresses concretes**.

Note : la conversion CIDR <-> masque (`10.0.0.0/8` <-> `10.0.0.0/255.0.0.0`)
est deja geree par `normaliseFirewallAddress`
(`internal/winclient/firewall_rule.go`, lignes ~418-449) — le refresh
post-echec sur 203 remontait bien les formes CIDR. Les deux mecanismes
restants (ordre, `any` combine) ne sont pas traites.

Reproduit a l'identique avec la config minimale `repro/F03` (run
`2611210137`, 2+2 adresses) : apply exit 1, 4 messages
(`element 1 has vanished` ici vu la liste plus courte), regle
`tfacc-2611210137-rf03` creee sur 203 puis nettoyee (`REMAINING:0`).

## Cause (sans modification de code — piste pour `provider-coder`)

- `local_address` / `remote_address` sont des `ListAttribute` ordonnes
  (`resource_windows_firewall_rule.go`, lignes ~309-339,
  `UseStateForUnknown`) ; le `Read` (`Norm-Arr` + `normaliseFirewallAddressArr`,
  `firewall_rule.go` lignes ~67-75 et ~442-449) preserve l'ordre renvoye
  par Windows, qui n'est pas celui du plan.
- `any` combine : aucun validateur n'impose `any` seul pour les adresses
  (contrairement a `CV-1` pour `profile`, lignes ~1015-1066) ; Windows
  ignore silencieusement `any` quand d'autres adresses sont presentes.

Correction suggeree (deux volets) :
1. Comparaison insensible a l'ordre — trier plan et etat (normalisation
   dans `modelToFirewallInput` + tri au `Read`/`firewallStateToModel`),
   ou migrer vers un `Set` (cassant : eviter). Valider sur 203 que l'ordre
   renvoye est stable entre deux `Read` successifs (sinon tri obligatoire).
2. `any` seul : ajouter un validateur plan-time `any`-doit-etre-seul pour
   `local_address`/`remote_address` (miroir de `CV-1`), diagnostic
   `Invalid address combination`, sans objet orphelin. Alternative :
   filtrer `any` quand combine — deconseille (silencieux, surprenant).

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE`
pointe sur le `terraform.rc` du run (dev_override vers le binaire provider
du run), en suivant la procedure `acc/lab-runner`.
Le prefixe est parametrable via `-var rule_prefix=...` (defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu
   **apres correction : exit 0**. Avant correction : exit 1
   (`inconsistent result`, ordre `local_address`, `remote_address`).
3. `terraform plan -detailed-exitcode -input=false -no-color` — attendu :
   exit 0 (`No changes`, pas de perpetual diff d'ordre).
4. Contre-check manuel `any` combine (apres le fix volet 2) :
   `remote_address = ["any", "203.0.113.7"]` en `plan` seul — attendu :
   exit 1 (`Invalid address combination`), sans objet cree sur 203.
5. `terraform destroy -auto-approve -input=false -no-color` — attendu : exit 0.
6. Verification sur 203 : regle `<prefix>-regress-f03` absente, aucun residu.

## Attendu

- Apply puis plan vide quelle que soit la permutation d'entree des
  adresses ; `any` combine refuse plan-time avec diagnostic propre.
- Aucun secret dans ce scenario, aucun fichier d'etat versionne.
