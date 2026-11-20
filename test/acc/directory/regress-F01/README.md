# regress-F01 — `attributes` non canonique : rejet au plan (contrat B+)

## Contexte

F01 (run 2611202011, scénario `13-inputs-attributes-dedup`, commit `0e03f64`) :
une liste `attributes` de 12 éléments avec doublons et ordre mélangé faisait
échouer `apply` avec `Provider produced inconsistent result after apply`
(`.attributes[0]`/`[1]` réécrits, éléments `3..11 has vanished`), la ressource
étant marquée tainted alors que le répertoire était bien créé sur 203 avec les
attributs normalisés `ReadOnly, Hidden, System, Directory`.

Cause : `attributes` est une `List` sans normalisation au plan
(`internal/provider/resource_windows_directory.go:129`), mais `Create`/`Update`
la font passer par `NormaliseDirectoryAttributes`
(`internal/winclient/directory_types.go:116`) qui déduplique et réordonne en
canonique `[hidden, readonly, system]` ; `applyDirectoryState` (`:299`)
réécrit l'état avec cette forme, qui ne correspond plus au plan. Toute
orthographe non canonique (doublons, ou même simple changement d'ordre comme
`["system", "hidden"]`) divergeait donc entre plan et état post-apply.

Repro minimale (2 éléments) : `work/acc/directory/2611202011/repro/F01/`
(`attributes = ["hidden", "hidden"]` → `element 1 has vanished`, `APPLY_EXIT=1`,
destroy ensuite `exit 0`, 203 propre).

## Fix retenu (B+, attempt 4)

Au lieu de normaliser (invalide par les tentatives 2 et 3, voir ci-dessous),
le provider **rejette au plan** toute orthographe non canonique via
`listvalidator.UniqueValues` + un validateur d'ordre custom, avec un
diagnostic explicite :

> `attributes must be unique and in canonical order: hidden, readonly, system`

Les valeurs inconnues, la casse non standard, `null`/`unknown` restent en
passthrough vers l'apply (comportement prouvé par les unit tests Go, verts
via Docker : gofmt/vet/tests OK). Les états existants contiennent déjà
l'orthographe canonique : aucune migration d'état requise.

## Étapes

1. `terraform init -input=false`
2. `terraform plan -input=false` → **attendu : exit 1**, diagnostic contenant
   `canonical order`. **Rien n'est créé sur 203.**
3. `terraform apply -auto-approve -input=false` → **attendu : exit 1** (même
   diagnostic, dès la phase de plan). **Rien n'est créé sur 203**, pas de
   taint (aucune ressource n'atteint l'apply).
4. Remplacer le bloc `attributes` par l'orthographe canonique
   `attributes = ["hidden", "readonly", "system"]`, puis
   `terraform apply -auto-approve -input=false` → **attendu : exit 0**
   (`Apply complete!`).
5. `terraform plan -detailed-exitcode -input=false` → **attendu : exit 0**
   (`No changes`, état canonique stable, aucun diff fantôme lié à l'ordre).
6. `terraform destroy -auto-approve -input=false` → **attendu : exit 0**,
   puis vérifier sur 203 que `C:\Windows\Temp\<prefix>-dedup` n'existe plus.

Remplacer `<prefix>` par la valeur de `var.name_prefix`.

(Ne pas lancer `destroy` avec la config non canonique des étapes 2-3 : la
config elle-même est rejetée à la validation, le destroy de sûreté se fait
avec la config canonique sur un état vide → no-op `exit 0`.)

## Attendu

- Étapes 2-3 : `exit 1` + diagnostic `canonical order`, aucun
  `inconsistent result after apply`, aucun `invalid plan`, rien sur 203.
- Étape 4 : `Apply complete!`, état `attributes = ["hidden", "readonly", "system"]`.
- Étape 5 : plan vide.
- Étape 6 : répertoire supprimé sur 203, aucun résidu `tfacc-*`.

## Bug observé (avant fix)

`Error: Provider produced inconsistent result after apply ... .attributes:
element 1 has vanished` (repro minimale) / `elements 9, 10, 11 likewise`
(scénario d'origine à 12 éléments).

## Tentative invalidée (attempt 3, binaire avec planmodifier)

Un `planmodifier.List` (`directoryAttributesNormalizeModifier`,
`internal/provider/resource_windows_directory.go:565-584`) qui déduplique et
trie au plan a été testé : le modificateur tourne (le plan affiche bien la
valeur normalisée), mais le cœur Terraform v1.16.5 rejette le plan —
`Error: Provider produced invalid plan ... planned value
[hidden, readonly, system] does not match config value [12 doublons]`
(`apply` exit 1 dès la phase de plan, `replan` exit 1 ; rien créé sur 203,
`destroy` exit 0, aucun résidu). Réécrire au plan une valeur de config `List`
connue et non nulle n'est donc pas une correction disponible sur cette
version du cœur, bien que l'attribut soit déjà `Optional+Computed`.
Voir `findings.yaml` (F01, `previous_attempts`) pour la stratégie retenue :
valideur imposant l'orthographe canonique (B+, attempt 4, unit tests verts,
en attente de validation rerun acceptance).

## Notes

- Aucun secret ; préfixe des objets Windows paramétrable via
  `var.name_prefix` (défaut `tfacc-f01`).
- Aucun state versionné dans ce dossier.
