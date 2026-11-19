# Regression F02 — apostrophe autorisee mais requete MWA cassee

## Contexte

Finding F02 (run `2611181908`, scenario `06-inputs-special-chars`, tentative 1) :
l'apostrophe `'` est autorisee par `ValidateIISSiteName`
(`internal/winclient/iis_site_types.go`, lignes ~124-138) et par le validateur
plan-time `iisSiteNameValidator`
(`internal/provider/resource_windows_iis_site.go`, lignes ~326-356), mais le
`Create` echoue avec :

```
Error: Error creating Windows IIS site [unknown]
Expected an operator name (eg. 'and')
Input:
get-config("MACHINE/WEBROOT/APPHOST")/system.applicationHost/sites/site[compare-string-ordinal(@name,'<nom>',true())=0]
Position: 132
```

Reproduction minimale confirmee dans `work/acc/iis_site/2611181908/repro/F02`
(nom `...-repro-f02-ap's`, apply exit 1, aucun site cree sur 203, destroy
final exit 0).

## Cause (sans modification de code — piste pour `provider-coder`)

`$Name` est interpole en toute securite dans les litteraux PowerShell via
`psQuote` (doublage de `'`), mais `Get-SiteData`
(`internal/winclient/iis_site.go`, lignes ~76-119) et `iisSitePreamble`
(lignes ~212-217) construisent aussi le filtre XPath
`system.applicationHost/sites/site[@name="<nom>"]` par concatenation. Le
fournisseur MWA normalise ce filtre en
`compare-string-ordinal(@name,'<nom>',true())` avec des guillemets simples, ou
l'apostrophe du nom termine le litteral : c'est une injection dans la requete
de configuration (impact observe : erreur, pas d'execution aveugle — le
fournisseur refuse de parser). L'en-tete du fichier (lignes ~16-27) documente
deja que "single-quote doubling is invalid in XPath 1.0", donc doubler `'`
dans le filtre ne suffirait pas.

Corrections suggerees (au choix) : resoudre les attributs sans filtre XPath
nomme (par ex. `Get-ItemProperty` via le chemin `IIS:\Sites\<nom>` au lieu de
`Get-WebConfigurationProperty -Filter $appFilter`), construire le predicat
avec `concat()` pour echapper l'apostrophe en XPath 1.0, ou interdire `'`
dans `ValidateIISSiteName` + validateur plan-time (redemarrage : divergences
avec les noms existants contenant `'` — a documenter).

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE` pointe
sur le `terraform.rc` du run (dev_override vers le binaire provider du run),
en suivant la procedure `acc/lab-runner`. Le prefixe est parametrable via
`-var site_prefix=...` (defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu **apres
   correction : exit 0** (site cree, nom stocke verbatim) **ou** refus propre
   a la validation si `'` est desormais interdit (diagnostic `Invalid IIS
   site name`, rien sur l'hote). Avant correction : exit 1, "Expected an
   operator name", aucun site sur 203.
3. `terraform plan -detailed-exitcode -input=false -no-color` (si apply OK) —
   attendu : exit 0 (vide).
4. `terraform destroy -auto-approve -input=false -no-color` — attendu : exit 0.
5. Verification sur 203 : aucun site `<prefix>-regress-f02-ap's`, dossier
   `C:\inetpub\<prefix>-regress-f02` supprime.

## Attendu

- Comportement deterministe pour un nom contenant `'` : creation verbatim ou
  refus de validation explicite — jamais d'erreur MWA `unknown`.
- Aucun secret dans ce scenario (noms/chemins uniquement), aucun fichier
  d'etat versionne.
