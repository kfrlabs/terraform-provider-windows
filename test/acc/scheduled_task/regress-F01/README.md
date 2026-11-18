# Regression F01 — import SYSTEM/ServiceAccount laisse `logon_type = null`

## Contexte

Finding F01 (run `2611181339`, scenario `05-import-external`, tentative 1) :
apres `terraform import` d'une tache planifiee Windows creee hors Terraform
(principal `SYSTEM` / `ServiceAccount` / `Limited`), l'etat contient
`principal = { user_id = "SYSTEM", logon_type = null, run_level = "Limited" }`
alors que le client winclient remonte bien `logon_type = "ServiceAccount"`
depuis `Get-ScheduledTask` (`Get-LogonTypeStr` dans
`internal/winclient/scheduled_task_scripts.go`).

Le plan post-import affiche donc un diff fantome :

```
~ principal = {
    + logon_type = "ServiceAccount"
    # (4 unchanged attributes hidden)
  }
```

Un `apply` fait converger (plus de perpetual diff), mais l'import ne produit
pas un etat propre alors que la configuration est a l'identique du reel.

## Cause (sans modification de code — piste pour `provider-coder`)

`buildPrincipalModel` dans `internal/provider/resource_windows_scheduled_task.go`
(lignes ~857-864) renseigne `logon_type` **uniquement** depuis le modele
pre-existant (`priorModel`). Sur le chemin import, `ImportState` appelle
`stateToModel(ctx, state, nil)` (ligne ~398) donc `priorModel == nil` et
`logon_type` reste `types.StringNull()`. La valeur observee
`ScheduledTaskPrincipalState.LogonType` n'est jamais utilisee.

Correction suggeree : sur le chemin import (`priorModel == nil`), peupler
`pm.LogonType` depuis `s.LogonType` quand il est non vide
(`types.StringValue(s.LogonType)`), en conservant la preservation depuis le
prior sinon (comportement anti-drift actuel sur Create/Read/Update).

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec
`TF_CLI_CONFIG_FILE` pointe sur le `terraform.rc` du run (dev_override vers
le binaire provider du run), en suivant la procedure `acc/lab-runner`.
Le prefixe est parametrable via `-var task_prefix=...` (defaut `tfacc`).

1. Creer la tache hors Terraform sur 203 (SSH) :
   ```powershell
   $act = New-ScheduledTaskAction -Execute 'C:\Windows\System32\cmd.exe'
   $trg = New-ScheduledTaskTrigger -AtStartup
   $prn = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Limited
   Register-ScheduledTask -TaskName '<prefix>-regress-f01' -TaskPath '\<prefix>-regress-f01\' `
     -Action $act -Trigger $trg -Principal $prn
   ```
2. `terraform init -input=false -no-color` — attendu : exit 0.
3. `terraform import -input=false -no-color windows_scheduled_task.repro '\<prefix>-regress-f01\<prefix>-regress-f01'` — attendu : exit 0.
4. `terraform show -json` — observer `values.principal.logon_type`.
5. `terraform plan -detailed-exitcode -input=false -no-color` — attendu
   **apres correction : exit 0** (`No changes`). Avant correction : exit 2
   avec `+ logon_type = "ServiceAccount"`.
6. `terraform destroy -auto-approve -input=false -no-color` — attendu : exit 0.
7. Verification sur 203 : `Get-ScheduledTask` ne retourne plus la tache
   (`ABSENT_OK`), aucun residu `tfacc*` sous le dossier du scenario.

## Attendu

- Import puis plan vide avec une configuration declaree a l'identique du
  reel (principal `SYSTEM`/`ServiceAccount`/`Limited`).
- Aucun secret dans ce scenario (pas de `password`/`password_wo`,
  `logon_type = ServiceAccount`), aucun fichier d'etat versionne.
