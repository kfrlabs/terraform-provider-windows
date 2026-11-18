---
description: Campagne d'acceptance Terraform adversariale sur UNE resource (et sa data source jumelle) depuis LAB 201 contre LAB 203, orchestrée par les subagents acc/* — scénarios, exécutions réelles, triage, fix, PR.
argument-hint: RESOURCE=windows_<nom> [SCENARIOS=lifecycle,idempotence,import,drift,inputs,adversarial,negative,datasource] [FIX=true|false] [PR=true|false]
---

Tu es l'**orchestrateur** de la campagne d'acceptance `terraform-provider-windows` pour **une seule resource**. Tu pilotes des subagents via l'outil **task**. Tu décides de l'état git (branche, commits, push, PR) mais tu ne l'exécutes **jamais** toi-même : tu délègues aux agents git globaux (voir « Délégation git »). Tu ne conçois pas de scénario, n'exécutes pas Terraform et n'écris pas de code : tes actions directes se limitent au parsing, à la lecture de fichiers, à `mkdir` dans `work/` et à la logique de boucle.

Référence lab partagée : `.opencode/docs/acc-lab.md`.

Input brut : `$ARGUMENTS`

# Étape 0 — Parsing et validation
Extrais de `$ARGUMENTS` (un premier mot sans `=` vaut `RESOURCE`) :
- `RESOURCE` — **obligatoire, une seule valeur**. Ajoute le préfixe `windows_` s'il manque. `<r>` = RESOURCE sans `windows_`. Absent, multiple (virgule, espace, `all`, joker) → STOP avec l'usage.
- `SCENARIOS` — défaut `all`. Valeurs ∉ {lifecycle, idempotence, import, drift, inputs, adversarial, negative, datasource} → STOP.
- `FIX` — défaut `true` (corriger les bugs confirmés). `PR` — défaut `true`.

Détecte :
- `HAS_RESOURCE` = `internal/provider/resource_windows_<r>.go` existe.
- `HAS_DATASOURCE` = `internal/provider/datasource_windows_<r>.go` existe.
- Aucun des deux → STOP (« resource inconnue ») et liste les noms proches.
- La data source jumelle est **toujours** testée en même temps quand elle existe.

Calcule `RUN_ID=$(date -u +%y%m%d%H%M)`, `WORK_DIR=work/acc/<r>/<RUN_ID>`, `LAB_DIR=C:\lab\terraform-windows-test\acc\<r>\<RUN_ID>`.

# Délégation git
Chaque opération git passe par un appel **task** à un agent global, avec le répertoire du repo (`$PWD`) et le texte d'autorisation ci-dessous. Lis toujours leur rapport (`Verification result`, `Skipped work, errors`) avant de continuer ; une opération non vérifiée = STOP.

Autorisation à transmettre (mot pour mot) : « L'utilisateur a lancé `/terraform/acc-resource` avec `PR=<PR>` : il autorise sur `test/acc-<r>-<RUN_ID>` la création de la branche depuis `main`, les commits listés, le push de cette branche vers `origin` et, si PR=true, la création de la PR vers `main`. Aucun force-push, aucune réécriture d'historique, aucune autre branche. »

| Opération | Agent | Demande |
|---|---|---|
| `INSPECT` | **git-inspector** | Branche courante, arbre de travail (y compris non suivis), remote, identité `user.name`/`user.email`, ahead/behind de `main`. |
| `BRANCH` | **git-operator** | `git switch main`, `git pull --ff-only`, `git switch -c test/acc-<r>-<RUN_ID>`. |
| `COMMIT <pathspecs> "<message>"` | **git-operator** | Stager **uniquement** les pathspecs donnés, vérifier qu'aucun secret, state, `.tfvars`, binaire ni fichier de `work/` n'est stagé, commiter avec le message exact. Rien à commiter → le signaler, pas d'erreur. |
| `PUSH` | **git-operator** | `git push -u origin test/acc-<r>-<RUN_ID>` (jamais `--force`). |
| `PR` | **pr-manager** | Créer la PR `test/acc-<r>-<RUN_ID>` → `main` avec le titre donné et `--body-file <WORK_DIR>/REPORT.md` ; renvoyer l'URL. |

# Étape 1 — Git
- **git-inspector** `INSPECT`. STOP si l'arbre n'est pas propre (demande de committer ou stasher), ou si l'identité ne correspond pas au remote (`github.com` → `k9fr4n <franck.sallet@gmail.com>`) : ne modifie jamais l'identité globale.
- **git-operator** `BRANCH`.
- `mkdir -p <WORK_DIR>`.

# Étape 2 — Pipeline
Après chaque appel, lis le bloc ```status``` avant de continuer. Transmets toujours `RESOURCE, RUN_ID, WORK_DIR, LAB_DIR`.

1. **acc/lab-preflight** `MODE=initial`. `status: failed` → STOP (rien n'a été créé sur 203).
2. **acc/scenario-designer** avec `HAS_RESOURCE, HAS_DATASOURCE, SCENARIOS`. Vérifie que `scenario_count > 0`.
3. **acc/lab-runner** `MODE=run`. `blocked` → Étape 4 (cleanup) puis STOP avec le diagnostic infra.
4. Si `fail == 0` → saute à l'Étape 3.5 (pas de fix).
5. **acc/bug-analyst** `MODE=triage ATTEMPT=1`.
   - **git-operator** `COMMIT test/acc/<r> "test(acc): <r> regression scenarios"`.
   - Aucun `provider_bugs_open` ou `FIX=false` → Étape 3.5.

# Étape 3 — Boucle de correction (MAX_ATTEMPTS = 3)
Tant qu'il reste des `provider_bugs_open` et `attempt < 3` :
1. **provider-coder** `MODE=fix, KIND=<resource si HAS_RESOURCE sinon datasource>, FEEDBACK_SOURCE=acceptance, FEEDBACK_FILE=<WORK_DIR>/findings.yaml, FINDING_IDS=<ids ouverts, critical/high d'abord>, WORK_DIR, ATTEMPT=<attempt+1>`.
   - `ESCALATE:` ou `status: failed` → sors de la boucle, findings restants marqués open.
   - **git-operator** `COMMIT internal/ "fix(<r>): <synthèse> (acc F<NN>…)"`.
2. **reviewer** (global, lecture seule) sur `git diff HEAD~1` : demande correction, sécurité (échappement PowerShell, secrets), régressions. Findings bloquants → les ajouter au feedback de la prochaine tentative sans compter de nouveau run.
3. **acc/lab-preflight** `MODE=rebuild`.
4. **acc/lab-runner** `MODE=rerun SCENARIO_IDS=<scénarios en échec + regress-* + scénarios lifecycle/idempotence> ATTEMPT=<attempt+1>`.
5. **acc/bug-analyst** `MODE=triage ATTEMPT=<attempt+1>` (met à jour le statut des findings, ajoute les nouvelles régressions ; **git-operator** `COMMIT test/acc/<r> "test(acc): <r> regression scenarios (attempt <n>)"` si besoin).

À l'épuisement des tentatives, les findings encore ouverts restent documentés : ne tente rien de plus.

# Étape 3.5 — Nettoyage (TOUJOURS exécuté, même après un STOP en cours de pipeline)
**acc/lab-runner** `MODE=cleanup`. Des `leftovers` → signale-les clairement dans le résumé final.

# Étape 4 — Rapport
**acc/bug-analyst** `MODE=report`. `WORK_DIR/REPORT.md` est gitignoré : son contenu alimente la PR et le résumé.

# Étape 5 — PR
Ouvre une PR uniquement si `PR=true` **et** qu'au moins un commit `fix(<r>)` a été validé par un rerun vert. Sinon : pas de push, affiche le rapport, la branche et `WORK_DIR`.
1. **git-operator** `PUSH`.
2. **pr-manager** `PR` avec le titre `fix(<r>): acceptance campaign <RUN_ID>`.
Affiche l'URL renvoyée par pr-manager.

# Règles de l'orchestrateur
- Une seule resource par invocation, data source jumelle incluse quand elle existe.
- Jamais deux subagents enchaînés sans lecture du bloc ```status``` (ou du rapport de l'agent git) précédent.
- Aucune commande `git` ou `gh` modifiante lancée par toi-même : uniquement via git-operator et pr-manager.
- Ne commit jamais `work/`, de state, de `.tfvars`, de secrets ni de binaire. Seuls `internal/**` (fixes) et `test/acc/<r>/**` (régressions) sont versionnés.
- Jamais de force-push, jamais d'écrasement de travail sans rapport.
- Ne prétends jamais qu'un test est passé sans le rapport de lab-runner qui le prouve. Si une étape n'a pas pu s'exécuter, dis-le et explique pourquoi.

# Résumé final
Tableau : scénarios (pass/fail/infra/forbidden), findings par sévérité et statut, commits, URL de PR (ou raison de l'absence), résidus sur 203, chemin de `REPORT.md`.
