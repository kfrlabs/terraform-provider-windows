# Regression F02 — recycling_schedule = ["05:15:30"] (secondes non nulles)

## Contexte

Finding F02 (run `2611221834`, scenario `04-inputs-schedule` step2,
tentative 2) : l'entree `05:15:30` passe le validateur schema
(`iisAppPoolScheduleRe` dans
`internal/provider/resource_windows_iis_app_pool_validators.go`, ligne ~83,
qui autorise des secondes quelconques) puis echoue a l'apply :

```
Error updating Windows IIS application pool [unknown]
Timespan value must be between 00:00:00 and 23:59:59 seconds inclusive, with
a granularity of 60 seconds
Context: operation=update, name=tfacc-2611221834-sched, step=update
```

Sonde directe sur 203 : entree `05:15:30` refusee, `05:15:00` acceptee. IIS
exige des entrees a la minute ronde (granularite 60 s). Reproduction
minimale confirmee dans `work/acc/iis_app_pool/2611221834/repro/F02`
(create exit 1, meme message, destroy exit 0, aucun residu sur 203).

## Cause (sans modification de code — piste pour `provider-coder`)

La regex du validateur autorise `[0-5]\d` en position secondes ; le
winclient injecte l'entree telle quelle via `Add-WebConfigurationProperty`
(`internal/winclient/iis_app_pool.go`, lignes ~195-205), donc l'echec sort
a l'apply au lieu du plan.

Correction suggeree : imposer des secondes a `00` dans
`iisAppPoolScheduleValidator` (ex.
``^([01]\d|2[0-3]):[0-5]\d:00$``), message et description du schema mis a
jour (`HH:MM:00`, minutes rondes). Aucun changement winclient requis.

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE` pointe
sur le `terraform.rc` du run (dev_override vers le binaire provider du run),
en suivant la procedure `acc/lab-runner`. Le prefixe est parametrable via
`-var pool_prefix=...` (defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform plan -input=false -no-color` — attendu **apres correction :
   exit 1** (entree `05:15:30` rejete, secondes autres que `00`). Avant
   correction : exit 0 (le plan passe et l'echec ne sort qu'a l'apply).
3. `terraform apply -auto-approve -input=false -no-color` — attendu apres
   correction : ne s'applique pas (plan rejete). Avant correction : exit 1
   avec l'erreur Timespan ci-dessus.
4. `terraform destroy -auto-approve -input=false -no-color` — attendu :
   exit 0 (rien a detruire).
5. Verification sur 203 : aucun pool `<prefix>-regress-f02`
   (`Get-ChildItem 'IIS:\AppPools'` sans correspondance).

## Attendu

- Rejet au plan (exit 1, secondes `00` exigées), pas d'echec a l'apply.
- Aucun orphelin : destroy exit 0, 203 sans residu.
- Aucun secret dans ce scenario (nom/horaire uniquement), aucun fichier
  d'etat versionne.
