# Regression F03 — conflit d'ID en parallele remonte NullReference au lieu de id_conflict

## Contexte

Finding F03 (run `2611181908`, scenario `20-negative-siteid-conflict`,
tentative 1) : deux sites partageant le meme `site_id` devaient echouer avec
un diagnostic `id_conflict`, mais l'apply echoue avec :

```
Error: Error creating Windows IIS site [unknown]
Object reference not set to an instance of an object.
Context: name=<perdant>, step=create, host=172.18.122.203, operation=create
```

Reproduction minimale confirmee dans `work/acc/iis_site/2611181908/repro/F03`
(apply exit 1, NRE sur `site_a` cette fois — le perdant de la course varie,
destroy final exit 0, 0 residu sur 203).

## Cause (sans modification de code — piste pour `provider-coder`)

Le garde pre-flight `$idClash` de `Create`
(`internal/winclient/iis_site.go`, lignes ~457-463) est une verification
TOCTOU : en creations paralleles (comportement par defaut de Terraform pour
des ressources sans dependance mutuelle), les deux `Create` passent le garde
avant que l'un des `New-Item` ne gagne l'ID. Le perdant recoit une
`NullReferenceException` brute du fournisseur IIS, que `Classify-Site`
(lignes ~121-125) + `Classify-IIS` (`internal/winclient/iis_common.go`,
lignes ~49-57) ne reconnaissent pas : elle tombe en `unknown` au lieu de
`id_conflict`. Le bloc `catch` (lignes ~484-502) ne re-verifie que le conflit
de **nom** (`already_exists`), jamais le conflit d'**ID**.

Correction suggeree : dans le `catch` de `Create`, quand un `SiteId` est
configure et que `New-Item` echoue, re-chercher un site portant cet ID
(`Get-ChildItem 'IIS:\Sites' | Where-Object { $_.ID -eq $SiteId }`) et
emettre `id_conflict` (avec `conflicting_site` en contexte, comme le garde
pre-flight) au lieu de l'erreur brute. Ne pas se contenter d'ajouter un motif
`NullReference` a `Classify-IIS` : ce message est trop generique et
masquerait d'autres pannes.

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE` pointe
sur le `terraform.rc` du run (dev_override vers le binaire provider du run),
en suivant la procedure `acc/lab-runner`. Le prefixe est parametrable via
`-var site_prefix=...` (defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu **apres
   correction : exit 1 avec diagnostic `[id_conflict]`** nommant le site en
   conflit (le perdant echoue proprement, le gagnant est cree). Avant
   correction : exit 1 avec `[unknown]` / NullReferenceException. Note : le
   perdant varie selon la course (parallelisme Terraform) — l'assertion porte
   sur le `kind`, pas sur le site.
3. `terraform destroy -auto-approve -input=false -no-color` — attendu : exit 0.
4. Verification sur 203 : aucun site `<prefix>-regress-f03-*`, dossier
   `C:\inetpub\<prefix>-regress-f03` supprime.

## Attendu

- Un conflit d'ID remonte toujours `id_conflict` (meme en creations
  paralleles), jamais `unknown`/NullReference.
- Aucun orphelin : destroy exit 0, 203 sans residu.
- Aucun secret dans ce scenario (noms/chemins/entiers uniquement), aucun
  fichier d'etat versionne.
