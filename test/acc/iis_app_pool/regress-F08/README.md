# Regression F08 — ecritures IIS concurrentes : `Object reference not set`

## Contexte

Finding F08 (run `2611231425`, scenarios `02-injection-name`,
`03-voluminous-recheck`, `06-parallel-pools`, tous en echec avec la meme
signature) : avec 2 a 3 pools independantes dans un seul `apply` (aucune
dependance, donc creations/destructions concurrentes sous le parallelisme
Terraform par defaut), environ une operation sur trois echoue par
intermittence avec :

```
Error: Error creating Windows IIS application pool [unknown]

Object reference not set to an instance of an object.

Context: name=tfacc-2611231425-par2, step=create, host=172.18.122.203,
operation=create
```

Le meme message apparait sur `delete` (scenarios 02 et 06 : une des trois
destructions echoue, l'etat Terraform conserve alors une ressource dont
l'objet a parfois deja disparu — etat orphelin). La reprise serielle
(`-parallelism=1`) reussit systematiquement, et la reproduction minimale a
ete confirmee dans `work/acc/iis_app_pool/2611231425/repro/F08` (3 pools aux
noms simples, attributs minimaux : 2 creates sur 3 en echec en parallele,
puis apply serial exit 0, destroy serial exit 0, 203 sans residu).

## Cause (sans modification de code — piste pour `provider-coder`)

Chaque operation IIS s'execute dans un `powershell.exe` 5.1 one-shot
(`runIISPowerShell`, `internal/winclient/iis_common.go`, ligne 93), hors
session persistante, et le client autorise jusqu'a `DefaultMaxSessions = 4`
appels concurrents (`internal/winclient/credentials.go`, ligne 89 ;
`acquire`/`release` dans `internal/winclient/client.go`, lignes 349-359).
Deux a trois ecrivains `WebAdministration` (`New-WebAppPool`,
`Set-ItemProperty`, `Remove-WebAppPool`) se retrouvent donc simultanement
sur `applicationHost.config`, et l'un d'eux recoit le `NullReference`
transitoire cote IIS (`Object reference not set`).

Le retry existant (`runAppPoolWrite`, `internal/winclient/iis_app_pool.go`,
lignes 317-372) ne couvre que la signature `Cannot commit configuration
changes ... file has changed on disk` (`IISConfigChangedOnDisk`,
`internal/winclient/iis_common.go`, lignes 204-208) : la signature
`Object reference` n'est matchee par aucun motif de `Classify-IIS`
(`internal/winclient/iis_common.go`, lignes 49-57) et remonte en `unknown`
sans retry.

Indices excluant les autres causes : l'echec frappe aussi des noms simples
(`par2`, `empty1` dans le run ; `r08a`/`r08c` dans le repro) et tourne entre
les ressources d'un run a l'autre (pas de nom deterministe) ; les memes
noms speciaux (`q'x`, `s$(7)`, `` b`k ``, `par$1`) passent en serie —
le quoting `psQuote` est donc correct, et les scenarios 04/05 prouvent un
203 sain (pas d'`infra_error`).

Correction suggeree : traiter le `NullReference` `WebAdministration`
(`Object reference not set to an instance of an object`) comme une erreur
transitoire d'ecriture IIS au meme titre que `file has changed on disk` —
meme boucle de retry (`iisWriteMaxAttempts`, backoff, `config_locked` si
persistance), de preference en restreignant le motif aux operations
d'ecriture create/update/delete pour ne pas masquer un vrai bug de lecture.
Le parallelisme multi-ressources est un usage standard (parallelisme 10 par
defaut), pas un stress test : la serialisation cote provider (`-parallelism=1`
en contournement) ne suffit pas comme reponse.

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE` pointe
sur le `terraform.rc` du run (dev_override vers le binaire provider du run),
en suivant la procedure `acc/lab-runner`. Le prefixe est parametrable via
`-var pool_prefix=...` (defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu **apres
   correction : exit 0** (`3 added`). Avant correction : exit 1 intermittent
   (`Object reference not set`, 1 a 2 ressources sur 3 en echec).
3. `terraform plan -detailed-exitcode -input=false -no-color` — attendu apres
   correction : exit 0 (aucun changement).
4. Verification sur 203 : `Get-ChildItem 'IIS:\AppPools'` contient les 3
   pools `<prefix>-regress-f08{a,b,c}`.
5. `terraform destroy -auto-approve -input=false -no-color` — attendu apres
   correction : exit 0, `3 destroyed` ; 203 sans residu (`Get-ChildItem
   'IIS:\AppPools'` sans correspondance). Avant correction : exit 1
   intermittent sur une des destructions.
6. L'echec etant intermittent, repeter les etapes 2 a 5 trois fois de suite
   avant de conclure : trois cycles verts consecutifs = regression fixee.

## Attendu

- Apply exit 0 en parallelisme par defaut, plan de refresh vide
  (detailed-exit 0), destroy exit 0, 203 sans residu.
- Aucun orphelin : plus d'etat conserve pour une pool disparue.
- Aucun secret dans ce scenario (noms uniquement), aucun fichier d'etat
  versionne.
