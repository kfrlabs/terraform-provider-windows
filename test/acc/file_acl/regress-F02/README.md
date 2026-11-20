# regress-F02 — droits en casse non canonique : apply OK puis plan vide

## Contexte

`windows_file_acl` documente des droits issus de l'enumeration
`FileSystemRights` (`FullControl`, `Read`, ...) sans exiger une casse
particuliere, et le client normalise ces mots-cles de facon insensible a la
casse (`CanonicalFileACLRight`, `NormaliseFileACLRights` dans
`internal/winclient/file_acl_types.go`, qui fusionne aussi `read`/`READ` en un
seul `Read`). Le chemin d'apply n'utilise d'ailleurs jamais les mots-cles :
le script PowerShell ne consomme que le `access_mask` calcule par Go.

Pourtant le validateur de schema
(`setvalidator.ValueStringsAre(stringvalidator.OneOf(...))` dans
`internal/provider/resource_windows_file_acl.go`) compare les chaines a
l'identique et rejette `fullcontrol`, `read` ou `READ` des la validation,
avant tout appel SSH. Rien n'est ecrit sur 203.

## Etapes

1. `terraform init -input=false`
2. `terraform validate -no-color` → **attendu : exit 0** (aucune erreur
   `Invalid Attribute Value Match` sur `access_rule[*].rights`)
3. `terraform apply -auto-approve -input=false` → **attendu : exit 0**
4. Sur 203, verifier les ACE explicites :
   ```powershell
   $P = 'C:\<prefix>\app.conf'
   (Get-Acl -LiteralPath $P).Access | Where-Object { -not $_.IsInherited } |
     ForEach-Object { '{0}:{1}' -f $_.IdentityReference.Value, $_.FileSystemRights }
   ```
   **attendu :** `BUILTIN\Administrators:FullControl` et
   `NT AUTHORITY\SYSTEM:Read` (le doublon `read`/`READ` est fusionne).
   Remplacer `<prefix>` par la valeur de `var.name_prefix`.
5. `terraform plan -detailed-exitcode -input=false` → **attendu : exit 0**
   (plan vide, pas de perpetual diff sur le bloc declare en minuscules)
6. `terraform destroy -auto-approve -input=false`, puis supprimer
   `C:\<prefix>` sur 203 si le repertoire subsiste.

## Bug observe

Run `2611201054`, scenario `06-inputs-rights-case-and-unicode` (repro
minimale rejouable : `work/acc/file_acl/2611201054/repro/F02/`, logs
`validate.log` / `apply.log`) :

- etape 2 : `exit 1`, `Attribute access_rule[0].rights[Value("fullcontrol")]
  value must be one of: [FullControl ...], got: "fullcontrol"` (idem pour
  `read` et `READ` sur la seconde regle) ;
- etape 3 : `exit 1` avec les memes diagnostics, avant tout appel SSH ;
- rien n'est cree sur 203 (`Test-Path ...\06-inputs-rights-case-and-unicode`
  = `False`), aucun state, aucun objet orphelin.

## Notes

- Aucun secret : SID bien connus et chemins uniquement.
- Prefixe des objets Windows parametrable via `var.name_prefix`
  (defaut `tfacc-f02`).
- Aucun state versionne dans ce dossier.
