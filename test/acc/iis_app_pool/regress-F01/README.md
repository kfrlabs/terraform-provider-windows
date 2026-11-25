# Regression F01 — recycling_periodic_restart_minutes = 525600 (365 j) au-dela du plafond IIS

## Contexte

Finding F01 (run `2611221834`, scenario `03-inputs-numeric-bounds` step2,
tentative 2) : `recycling_periodic_restart_minutes = 525600` passe le
validateur schema (`int64validator.AtLeast(0)` dans
`internal/provider/resource_windows_iis_app_pool_schema.go`, ligne ~276)
puis echoue a l'apply :

```
Error updating Windows IIS application pool [unknown]
Timespan value must be between 00:00:00 and 300.00:00:00 seconds inclusive,
with a granularity of 60 seconds
Context: operation=update, name=tfacc-2611221834-nb, step=update
```

Sonde directe sur 203 : 525600 refuse, 432000 (300 j) accepte. Le plafond
serveur est donc 300 jours = 432000 minutes. Reproduction minimale confirmee
dans `work/acc/iis_app_pool/2611221834/repro/F01` (create exit 1, meme
message, destroy exit 0, aucun residu sur 203).

## Cause (sans modification de code — piste pour `provider-coder`)

Le schema ne connait pas le plafond serveur ; le winclient transmet les
minutes telles quelles a `New-TimeSpan -Minutes`
(`internal/winclient/iis_app_pool.go`, ligne ~186) sans clamp, et l'erreur
remonte en `unknown` a l'apply au lieu d'un rejet au plan.

Correction suggeree : `int64validator.Between(0, 432000)` sur
`recycling_periodic_restart_minutes`, description du schema mentionnant le
plafond IIS (300 j). Aucun changement winclient requis.

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE` pointe
sur le `terraform.rc` du run (dev_override vers le binaire provider du run),
en suivant la procedure `acc/lab-runner`. Le prefixe est parametrable via
`-var pool_prefix=...` (defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform plan -input=false -no-color` — attendu **apres correction :
   exit 1** (`between 0 and 432000`). Avant correction : exit 0 (le plan
   passe et l'echec ne sort qu'a l'apply).
3. `terraform apply -auto-approve -input=false -no-color` — attendu apres
   correction : ne s'applique pas (plan rejete). Avant correction : exit 1
   avec l'erreur Timespan ci-dessus.
4. `terraform destroy -auto-approve -input=false -no-color` — attendu :
   exit 0 (rien a detruire).
5. Verification sur 203 : aucun pool `<prefix>-regress-f01`
   (`Get-ChildItem 'IIS:\AppPools'` sans correspondance).

## Attendu

- Rejet au plan (exit 1, `between 0 and 432000`), pas d'echec a l'apply.
- Aucun orphelin : destroy exit 0, 203 sans residu.
- Aucun secret dans ce scenario (nom/entier uniquement), aucun fichier
  d'etat versionne.
