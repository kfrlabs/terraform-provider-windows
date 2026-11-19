# Regression F01 — site_id = 4294967295 ignore silencieusement par IIS

## Contexte

Finding F01 (run `2611181908`, scenario `02-inputs-siteid-max`, tentative 1) :
`site_id = 4294967295` passe le validateur `Between(1, 4294967295)` mais IIS
ignore la valeur : le site est cree avec l'ID libre le plus bas (observe :
`2`). Le provider renvoie l'etat observe sans le reconcilier avec le plan,
donc Terraform echoue avec :

```
Error: Provider produced inconsistent result after apply
... .site_id: was cty.NumberIntVal(4.294967295e+09), but now cty.NumberIntVal(2).
```

En cascade, le premier `destroy` du scenario a echoue sur le site divergeant
(`Error deleting Windows IIS site [unknown] / Object reference not set to an
instance of an object`), necessitant un `cleanup_ps` manuel avant un second
`destroy` propre. Reproduction minimale confirmee dans
`work/acc/iis_site/2611181908/repro/F01` (apply exit 1, site reel d'ID 2).

## Cause (sans modification de code — piste pour `provider-coder`)

`Create` dans `internal/winclient/iis_site.go` (lignes ~445-521) transmet
`$SiteId` a `New-Item` sans verifier qu'IIS l'a honore, et la couche provider
(`Create` dans `internal/provider/resource_windows_iis_site.go`, lignes
~461-504) persiste l'etat observe tel quel. Quand l'ID relu differe de l'ID
planifie, le framework leve "inconsistent result" au lieu d'un diagnostic
actionnable.

Corrections suggerees (au choix, ne pas combiner sans arbitrage) :
renvoyer une erreur propre quand l'ID relu differe de l'ID demande
(`id_mismatch`/`id_conflict` avec `name`/`site_id` en contexte, site partiel
nettoye best-effort comme les autres echecs de `Create`), ou resserrer le
validateur sur le maximum reellement accepte par le fournisseur MWA
(IIS ignore 4294967295 = 0xFFFFFFFF, probablement un `int32` cote
fournisseur, soit un plafond a 2147483647 — a verifier sur 203 avant de
trancher).

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE` pointe
sur le `terraform.rc` du run (dev_override vers le binaire provider du run),
en suivant la procedure `acc/lab-runner`. Le prefixe est parametrable via
`-var site_prefix=...` (defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu **apres
   correction : echec propre** (diagnostic provider nommant `site_id`, pas
   de "inconsistent result after apply"). Avant correction : exit 1 avec
   "inconsistent result after apply" (`.site_id` planifie 4294967295, relu 2).
3. `terraform destroy -auto-approve -input=false -no-color` — attendu : exit 0.
4. Verification sur 203 : aucun site `<prefix>-regress-f01`
   (`Get-Website -Name '<prefix>-regress-f01'` absent), dossier
   `C:\inetpub\<prefix>-regress-f01` supprime.

## Attendu

- Pas de "inconsistent result after apply" : un `site_id` qu'IIS n'honore pas
  produit un diagnostic provider explicite (ou est rejete a la validation).
- Aucun orphelin : destroy exit 0, 203 sans residu.
- Aucun secret dans ce scenario (noms/chemins/entiers uniquement), aucun
  fichier d'etat versionne.
