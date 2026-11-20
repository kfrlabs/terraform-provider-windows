# regress-F01 — import d'une cible protegee : le plan post-import doit etre vide

## Contexte

`terraform import` adopte un descripteur existant (protege, une seule entree
explicite FullControl pour `S-1-5-32-544`). Quand la configuration decrit
exactement ce descripteur (identite orthographiee en SID,
`preserve_inherited_on_protect = false`), le plan qui suit l'import doit etre
vide (`detailed_exit 0`).

## Etapes

1. `terraform init -input=false`
2. `terraform apply -target=windows_file.app -auto-approve -input=false`
   (fixture : le fichier existe avec son DACL herite par defaut)
3. Sur 203, poser le DACL deterministe hors bande :
   ```powershell
   $ErrorActionPreference = 'Stop'
   $P = 'C:\<prefix>\app.conf'
   $acl = Get-Acl -LiteralPath $P
   $acl.SetAccessRuleProtection($true, $false)
   foreach ($e in @($acl.GetAccessRules($true,$false,[System.Security.Principal.SecurityIdentifier]))) {
     [void]$acl.RemoveAccessRuleSpecific($e)
   }
   $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
   $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
     $sid, [System.Security.AccessControl.FileSystemRights]::FullControl,
     [System.Security.AccessControl.InheritanceFlags]::None,
     [System.Security.AccessControl.PropagationFlags]::None,
     [System.Security.AccessControl.AccessControlType]::Allow)))
   Set-Acl -LiteralPath $P -AclObject $acl
   ```
   Remplacer `<prefix>` par la valeur de `var.name_prefix`.
4. `terraform import windows_file_acl.test 'C:\<prefix>\app.conf'` → `exit 0`
5. `terraform plan -detailed-exitcode -input=false` → **attendu : exit 0**
   (plan vide)
6. `terraform destroy -auto-approve -input=false`, puis supprimer
   `C:\<prefix>` sur 203 si le repertoire subsiste.

## Attendu

- Etape 5 : `No changes. Your infrastructure matches the configuration.`
  (`detailed_exit 0`), et le plan reste vide apres un `apply`
  (pas d'update fantome, pas de perpetual diff).
- `terraform plan` ne propose ni `~ identity`, ni
  `~ preserve_inherited_on_protect`, ni `(known after apply)` sur
  `effective_access_rules` / `owner_sid` / `sddl`.

## Bug observe

Tentative 1 : l'etape 5 sortait en `exit 2` avec :

- `~ identity = "BUILTIN\\Administrators" -> "S-1-5-32-544"` : l'import
  synthetisait les blocs `access_rule` avec le nom d'affichage observe, et
  Terraform comparait config et etat au sens strict (pas d'equivalence SID).
- `~ preserve_inherited_on_protect = true -> false` : `ImportState`
  forcait `true` et `Read` ne le reconciliait jamais (flag non observable
  sur l'hote une fois la protection appliquee).

Tentative 2 (fix partiel, run 2611200919) : les deux diffs geres ci-dessus
sont leves (etat `identity='S-1-5-32-544'`, suppression `preserve` active,
planfile JSON `after==before` sur tout le gere), mais l'etape 5 reste en
`exit 2`, pilote UNIQUEMENT par
`effective_access_rules / owner_sid / sddl -> (known after apply)`.
Le marquage ne converge jamais : plan sans `apply` toujours `exit 2`,
`apply` fantome (`0 added, 1 changed`, meme descripteur reecrit), puis plan
post-apply toujours `exit 2` avec la meme signature. Perpetual diff :
preuves dans `work/acc/file_acl/2611200919/logs/05-import-file-plan-empty/`
(`05-a2-06`, `05-a2-13`, `05-a2-15`, `05-a2-17`) et `logs/regress-F01/`
(`F01-a2-06`). Voir `repro/F01/plan-after-import.log` (artefact du run
2611200919, non versionne).

## Notes

- Aucun secret : SID et chemins uniquement.
- Prefixe des objets Windows parametrable via `var.name_prefix`
  (defaut `tfacc-f01`).
- Aucun state versionne dans ce dossier.
