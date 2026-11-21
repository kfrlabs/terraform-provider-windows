# Regression F04 — `Update` ne reinitialise pas `description` (stale Read)

## Contexte

Finding F04 (run `2611210137`, scenario `06-inputs-optional-transitions`
step3, tentative 1) : apres step1 minimal -> step2 full (`description =
"full config step2"`, apply OK, plan vide OK), le retour step3 minimal
(`description` omise, donc `null`) echoue :

```
Error: Provider produced inconsistent result after apply
... .description: was null, but now "full config step2".
```

Le plan step3 voulait `- description = "full config step2" -> null`
(apply exit 1), et le plan suivant montre le diff persistant
(`- description = "full config step2" -> null`, perpetual diff si le
Create avait reussi). La regle 203 gardait l'ancienne description.

Reproduit a l'identique avec la config minimale `repro/F04`
(step1 avec description -> step2 sans) : step1 apply exit 0, step2 apply
exit 1 (`.description: was null, but now "repro F04 description step1"`).
Destroy step2 OK, `REMAINING:0` verifie sur 203.

## Cause (sans modification de code — piste pour `provider-coder`)

- `buildFirewallParams` (`internal/winclient/firewall_rule.go`, lignes
  ~300-302) n'emet `Description = ...` que si `input.Description != ""`.
- `modelToFirewallInput` (`internal/provider/resource_windows_firewall_rule.go`,
  lignes ~676-720) mappe `Description` via `ValueString()` : `null` et
  `""` deviennent tous deux `""`.
- Sur le chemin `Update`, l'absence du parametre fait que
  `Set-NetFirewallRule` (frUpdateBody, `firewall_rule.go` lignes ~197-209)
  conserve l'ancienne description ; le `Read` post-Update la remonte,
  d'ou le mismatch plan (`null`) vs etat (`"full config step2"`).
- Meme racine probable pour les autres optionnels effacables du volet
  (a auditer : `program`/`service`/`interface_type`/`edge_traversal_policy`
  et listes videes — ici seul `description` est prouve par le run).

Correction suggeree : sur le chemin `Update` uniquement, emettre
explicitement la reinitialisation quand le plan est `null`/vide
(`-Description` vide/`$null` selon la semantique `Set-NetFirewallRule`
a valider sur 203 — `Set-NetFirewallRule -Description ''` vs omettre),
sans changer le chemin `Create` (omettre = defaut Windows, OK).
Distinguer `null` de `""` dans `modelToFirewallInput` si besoin (passer un
marqueur d'absence au lieu de `""`).

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE`
pointe sur le `terraform.rc` du run (dev_override vers le binaire provider
du run), en suivant la procedure `acc/lab-runner`.
Le prefixe est parametrable via `-var rule_prefix=...` (defaut `tfacc`).
`step1/` et `step2/` partagent le meme state : appliquer depuis un seul
dossier de travail (copier le `main.tf` voulu) ou deux dossiers avec le
meme backend local — suivre la procedure du scenario 06 du run (step1
puis step2 dans le meme `<id>`).

1. `terraform init -input=false -no-color` (dossier step1) — exit 0.
2. `terraform apply -auto-approve -input=false -no-color` (step1) — exit 0.
3. Basculer sur la config step2 (meme state), `terraform apply
   -auto-approve -input=false -no-color` — attendu **apres correction :
   exit 0**. Avant correction : exit 1 (`inconsistent result`,
   `.description was null, but now ...`).
4. `terraform plan -detailed-exitcode -input=false -no-color` (step2) —
   attendu : exit 0 (`No changes`).
5. Verification sur 203 : `Description` vide/absente sur
   `Get-NetFirewallRule -Name '<prefix>-regress-f04'`.
6. `terraform destroy -auto-approve -input=false -no-color` — exit 0 ;
   regle absente sur 203, aucun residu.

## Attendu

- Transition full -> minimal efface `description` sur 203, apply puis plan
  vide.
- Aucun secret dans ce scenario, aucun fichier d'etat versionne.
