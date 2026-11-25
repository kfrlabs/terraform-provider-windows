# Regression F05 — `recycling_periodic_restart_minutes = 432000` relu a 0

## Contexte

Finding F05 (run `2611231224`, scenarios `01-datasource-coherence`,
`03-idempotence-restart-max` et `04-import-recheck`) : avec
`recycling_periodic_restart_minutes = 432000` (300 j, borne F01 valide),
l'apply echoue avec :

```
Error: Provider produced inconsistent result after apply
[...] .recycling_periodic_restart_minutes: was cty.NumberIntVal(432000),
but now cty.NumberIntVal(0).
```

L'ecriture reussit sur 203 (`periodicRestart.time = 300.00:00:00` confirme
via `Get-WebConfiguration`), mais la relecture retourne 0. Reproduction
minimale confirmee dans `work/acc/iis_app_pool/2611231224/repro/F05`
(apply exit 1, meme message, destroy exit 0, aucun residu sur 203).

## Cause (sans modification de code — piste pour `provider-coder`)

`Get-AppPoolData` lit le delai via le PSDrive IIS
(`internal/winclient/iis_app_pool.go`, ligne 88) :

```powershell
recycling_periodic_restart_minutes = [int64]$p.'recycling.periodicRestart.time'.TotalMinutes
```

Sur 203 (Server 2025, WebAdministration), cette propriete pointillee vaut
`$null` — pas seulement pour 300 j : sondes directes `60 min` et `29 h`
(defaut `1.05:00:00`) retournent aussi `NULL` via `Get-ItemProperty
'IIS:\AppPools\...'`, alors que `Get-WebConfiguration
'system.applicationHost/applicationPools/add[@name="..."]/recycling/periodicRestart'`
retourne `.time = 01:00:00` / `300.00:00:00` correctement. `$null.TotalMinutes`
vaut `$null`, et `[int64]$null` vaut `0` : tout restart non nul est donc relu
a 0 (meme mecanisme suspect pour `recycling.periodicRestart.privateMemory`,
ligne 90 : `102400` ecrit relu `[]` via IIS: contre `102400` via
`Get-WebConfiguration`).

Correction suggeree : lire la section `recycling/periodicRestart` via
`Get-WebConfiguration` (comme l'ecriture le fait deja via
`Add-WebConfigurationProperty`) au lieu du PSDrive IIS — pour `.time` (et
probablement `.privateMemory`), en convertissant le `TimeSpan` en minutes
rondes cote serveur comme aujourd'hui.

Le demi-echec schedule de `04-import-recheck` (schedule `null` apres import)
est, lui, volontaire et documente (`ImportState` neutralise le schedule,
`internal/provider/resource_windows_iis_app_pool.go` lignes 435-436 et
487-489 ; `recycling_schedule` null = non gere) : voir finding F06
(`expected_limitation`), pas de fix provider.

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE` pointe
sur le `terraform.rc` du run (dev_override vers le binaire provider du run),
en suivant la procedure `acc/lab-runner`. Le prefixe est parametrable via
`-var pool_prefix=...` (defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu **apres
   correction : exit 0** (`Creation complete`, `restart_minutes = 432000`).
   Avant correction : exit 1 (`inconsistent result ... 432000 -> 0`).
3. `terraform plan -detailed-exitcode -input=false -no-color` — attendu apres
   correction : exit 0 (aucun changement).
4. Verification sur 203 : `Get-WebConfiguration
   'system.applicationHost/applicationPools/add[@name="<prefix>-regress-f05"]/recycling/periodicRestart'`
   montre `time = 300.00:00:00`.
5. `terraform destroy -auto-approve -input=false -no-color` — attendu :
   exit 0, 1 destroyed ; 203 sans residu (`Get-ChildItem 'IIS:\AppPools'`
   sans correspondance).

## Attendu

- Apply exit 0, plan de refresh vide (detailed-exit 0), output
  `restart_minutes = 432000`.
- Aucun orphelin : destroy exit 0, 203 sans residu.
- Aucun secret dans ce scenario (nom/entier uniquement), aucun fichier
  d'etat versionne.
