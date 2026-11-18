---
description: Enchaîne plusieurs cycles /terraform/acc-resource sur UNE resource, avec des paramètres différents à chaque cycle, pour chercher et corriger un maximum de bugs. Chaque cycle produit et pousse son propre commit.
argument-hint: RESOURCE=windows_<nom> [CYCLES=4] [PLAN="lifecycle,idempotence,import;inputs,negative;..."] [STOP_WHEN_CLEAN=2] [PR=true|false]
---

Tu es l'**orchestrateur de cycles** de campagnes d'acceptance `terraform-provider-windows`. Un cycle = une exécution complète de `/terraform/acc-resource` avec ses propres paramètres. Les cycles sont **strictement séquentiels** (le lab est partagé). Comme pour `/terraform/acc-resource`, tu ne lances toi-même aucune commande `git` ou `gh` modifiante : tu délègues aux agents git globaux.

Input brut : `$ARGUMENTS`

# Étape 0 — Parsing et validation
Extrais de `$ARGUMENTS` (un premier mot sans `=` vaut `RESOURCE`) :
- `RESOURCE` — **obligatoire, une seule valeur** (mêmes règles et même détection `HAS_RESOURCE` / `HAS_DATASOURCE` que `/terraform/acc-resource`). `<r>` = RESOURCE sans `windows_`.
- `CYCLES` — défaut `4`, entre 1 et 10.
- `PLAN` — optionnel : un jeu de `SCENARIOS` par cycle, séparés par `;` (ex. `lifecycle,import;inputs,negative`). Plus court que `CYCLES` → on reboucle sur le plan.
- `STOP_WHEN_CLEAN` — défaut `2` : arrêt anticipé après N cycles consécutifs sans nouveau `provider_bug`. `0` = jamais.
- `PR` — défaut `true`.

Calcule `TS=$(date -u +%y%m%d%H%M)`, `BRANCH=test/acc-cycles-<r>-<TS>`, `CYCLES_DIR=work/acc/<r>/cycles-<TS>`.

## Plan par défaut (sans `PLAN`)
| Cycle | `SCENARIOS` | `FOCUS` |
|---|---|---|
| 1 | `lifecycle,idempotence,import` | CRUD de base, ForceNew vs in-place, import puis plan vide. |
| 2 | `inputs,negative` | Bornes, Unicode, caractères spéciaux, combinaisons invalides, transitions optional/computed. |
| 3 | `adversarial,drift` | Injection PowerShell, sorties inattendues, modifications et suppressions externes, apply interrompu. |
| 4 | `datasource,idempotence,import` si `HAS_DATASOURCE`, sinon `inputs,adversarial` | Cohérence data source / resource, refresh répété ; sinon angles d'entrées non couverts. |
| 5+ | reboucle sur 1 → 4 | Angles **non couverts** par les cycles précédents et zones de code modifiées par les fixes déjà commités. |

À chaque cycle, `FOCUS` est complété par : « Revérifier les findings corrigés aux cycles précédents (<ids>) et cibler les zones touchées par leurs fixes. »

# Délégation git
Autorisation à transmettre (mot pour mot) à chaque agent git : « L'utilisateur a lancé `/terraform/acc-cycles` avec `PR=<PR>` : il autorise sur `<BRANCH>` la création de la branche depuis `main`, un commit par cycle, le push de cette branche vers `origin` après chaque cycle et, si PR=true, la création d'une PR vers `main` à la fin. Il autorise aussi le `git stash push` des corrections non validées d'un cycle. Aucun force-push, aucune réécriture d'historique, aucune autre branche. »

- **git-inspector** `INSPECT` : arbre propre et identité cohérente avec le remote (`github.com` → `k9fr4n <franck.sallet@gmail.com>`), sinon STOP.
- **git-operator** `BRANCH` : `git switch main`, `git pull --ff-only`, `git switch -c <BRANCH>`.
- **git-operator** `PUSH` : `git push -u origin <BRANCH>` (jamais `--force`).
- **pr-manager** `PR` : PR `<BRANCH>` → `main`, titre `fix(<r>): acceptance cycles <TS>`, `--body-file <CYCLES_DIR>/SUMMARY.md`.

# Étape 1 — Préparation
1. **git-inspector** `INSPECT`, puis **git-operator** `BRANCH`.
2. `mkdir -p <CYCLES_DIR>` et initialise `<CYCLES_DIR>/SUMMARY.md` (outil write) : resource, branche, plan prévu.

# Étape 2 — Boucle de cycles
Pour `n = 1 … CYCLES` :
1. Détermine `SCENARIOS_n` et `FOCUS_n` (plan ci-dessus ou `PLAN`). `AVOID_n` = chemins des `scenarios.yaml` des cycles précédents.
2. **Lance le cycle** : relis `.opencode/commands/terraform/acc-resource.md` et applique-le **intégralement**, en remplaçant `$ARGUMENTS` par :
   `RESOURCE=<RESOURCE> SCENARIOS=<SCENARIOS_n> FOCUS="<FOCUS_n>" AVOID=<AVOID_n> BRANCH=<BRANCH> COMMIT=cycle CYCLE=<n> FIX=true PR=false`
   Toutes ses règles s'appliquent (délégation git, nettoyage du lab toujours exécuté, aucune affirmation sans preuve).
3. Lis le bloc ```cycle-status``` de fin de cycle.
   - `status: blocked` (lab inutilisable) ou `failed` → arrête la boucle (Étape 3).
   - `commit` non vide → **git-operator** `PUSH`. Push non vérifié → arrête la boucle.
4. Ajoute au `SUMMARY.md` une section `## Cycle <n>` : paramètres, `RUN_ID`, scénarios pass/fail, findings (corrigés / ouverts / sévérité), commit, lien vers `work/acc/<r>/<RUN_ID>/REPORT.md`, stash éventuel de corrections non validées.
5. Arrêt anticipé si les `STOP_WHEN_CLEAN` derniers cycles n'ont trouvé aucun nouveau `provider_bug`.

# Étape 3 — Fin
- Ajoute au `SUMMARY.md` un bilan : cycles exécutés et raison d'arrêt, total des bugs trouvés et corrigés, findings encore ouverts, résidus sur 203.
- Si `PR=true` et qu'au moins un commit de cycle a été poussé → **pr-manager** `PR`. Sinon, pas de PR.

# Règles
- Une seule resource, cycles jamais en parallèle, un `RUN_ID` distinct par cycle.
- Un cycle ne commence que si l'arbre de travail est propre (le cycle précédent a commité ou mis de côté ses changements).
- Ne réécris jamais l'historique : un cycle qui échoue ne touche pas aux commits des cycles précédents.
- `work/` n'est jamais commité ; `SUMMARY.md` sert de corps de PR et de rapport final.

# Résumé final
Tableau par cycle : `SCENARIOS`, pass/fail, bugs trouvés, bugs corrigés, commit poussé. Puis l'URL de la PR (ou la raison de son absence), les findings encore ouverts, les stashes de corrections non validées et le chemin de `SUMMARY.md`.
