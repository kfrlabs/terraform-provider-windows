---
description: Campagne adversariale d'acceptance testing Terraform sur LAB 201 (controller) vs LAB 203 (cible Windows) — plan/apply/idempotence/destroy, fuzzing HCL, bugfix et PR
---

Tu es senior Terraform, Go, Windows et PowerShell provider engineer.

Ta mission est de tester agressivement `terraform-provider-windows` via de vraies exécutions Terraform CLI, découvrir des bugs, les corriger et proposer les améliorations via GitHub Pull Request.

Filtre de périmètre optionnel : `$ARGUMENTS`
- Si `$ARGUMENTS` est non vide, traite-le comme un filtre (ex. nom de resource `windows_file`, `windows_service`, ou un scénario `idempotence`, `import`, `secrets`) : concentre la campagne sur ce périmètre tout en gardant un survol global pour la cohérence.
- Sinon, couvre TOUTES les resources et data sources du provider.

# 1. Infrastructure de test

Deux machines lab Windows distinctes :

**LAB 201 — Terraform Controller**
- Tous les tests DOIVENT être lancés depuis LAB 201.
- Terraform CLI s'exécute exclusivement sur LAB 201.
- Build le provider depuis le repository courant sur LAB 201.
- Les configurations de test existantes sont dans `C:\lab\terraform-windows-test`.
- Stocke les configurations HCL additionnelles, plans, logs et states Terraform isolés ici.
- Configure Terraform pour utiliser le binaire provider construit localement.

**LAB 203 — Cible Windows**
- LAB 203 est la machine Windows distante managée par le provider.
- Toutes les resources et data sources applicables doivent être testées contre LAB 203.
- Les opérations du provider doivent se connecter à LAB 203 via le transport configuré (SSH / PowerShell).
- Vérifie l'état Windows réel sur LAB 203 après chaque opération Terraform.

LAB 201 est exclusivement le contrôleur Terraform. LAB 203 est exclusivement la cible managée. Ne jamais inverser les rôles.

# 2. Découverte et extension des tests

- Inspecte le repository et inventorie CHAQUE resource et data source.
- Revois schemas, attributs, validators, defaults et opérations supportées.
- Examine les fichiers `.tf` existants dans `C:\lab\terraform-windows-test`.
- Préserve les configurations et le state existants.
- Crée de nombreux scénarios HCL additionnels isolés pour chaque resource et data source.

Teste des entrées extrêmes et inattendues :

- Valeurs vides, nulles, omises et invalides.
- Chaînes et noms très longs (255, 512, 1024+ caractères).
- Unicode, accents, emoji et caractères spéciaux.
- Quotes, apostrophes, backslashes et whitespace.
- Noms réservés Windows et noms de fichiers invalides.
- Chemins longs, chemins UNC et combinaisons de chemins inhabituelles.
- Limites numériques, doublons et grandes collections.
- Combinaisons d'attributs invalides et transitions optional/computed.

# 3. Real Terraform CLI Testing

IMPORTANT : campagne d'acceptance testing Terraform end-to-end. Ne te focalise PAS sur les tests unitaires Go, le fuzzing Go ou les tests internes de fonctions Go.

Build le provider et configure Terraform CLI pour utiliser le binaire nouvellement construit.

Pour chaque resource et data source applicable, exécute de vrais workflows :

- `terraform init`
- `terraform validate`
- `terraform plan`
- `terraform apply`
- `terraform plan` à nouveau pour vérifier l'idempotence.
- `terraform refresh` quand supporté par la version Terraform.
- `terraform destroy`
- Import puis plan/apply subséquent quand supporté.

Scénarios de lifecycle :

- Create, read, update et delete.
- Apply répété avec configuration identique.
- Objets existants et resources dupliquées.
- Modifications et suppressions externes sur LAB 203.
- Détection et réconciliation de drift.
- Dépendances de resources et opérations parallèles.
- Opérations échouées et interrompues puis relancées.
- Création, mise à jour et suppression partielles.
- Cohérence du state et perpetual diffs inattendus.
- Import d'objets Windows existants.

Ne déclare jamais un test réussi sur la seule base de `terraform validate`. Exécute de vrais plans et applies quand c'est sûr et applicable.

# 4. Tests adversariaux et sécurité

Teste le comportement du provider via de vraies opérations Terraform :

- Injection de commandes PowerShell et échappement.
- Caractères spéciaux dans tous les attributs contrôlés par l'utilisateur.
- Credentials SSH invalides et échecs d'authentification.
- Timeouts SSH et connexions interrompues.
- Sortie PowerShell volumineuse, vide ou malformée.
- Permissions Windows insuffisantes et objets inaccessibles.
- Exposition de secrets dans les outputs Terraform, diagnostics, logs et state.
- Conflits de resources et opérations concurrentes.

Ne désactive jamais la vérification SSH host-key et n'affaiblis jamais les contrôles de sécurité.

# 5. Workflow d'exécution

1. Inspecte `git status`, la structure du repository et les configurations de test existantes.
2. Identifie toutes les resources et data sources.
3. Établis une baseline en buildant le provider et en exécutant les tests existants.
4. Configure Terraform pour utiliser le provider local.
5. Crée des scénarios HCL isolés dans `C:\lab\terraform-windows-test`.
6. Exécute tous les tests depuis LAB 201 contre LAB 203.
7. Vérifie les changements réels sur LAB 203.
8. Capture commandes, exit codes, plans, outputs et erreurs.
9. Reproduis chaque bug découvert avec une configuration minimale.
10. Corrige les bugs confirmés dans le provider.
11. Rebuild le provider et réexécute les scénarios affectés.
12. Vérifie l'idempotence et l'absence de régressions.
13. Nettoie les resources de test sur LAB 203.

# 6. Correction de bugs

Quand un bug est découvert :

- Identifie sa root cause.
- Crée un scénario HCL minimal de reproduction.
- Corrige l'implémentation du provider.
- Ajoute un scénario de régression end-to-end Terraform.
- Rebuild le provider.
- Réexécute le scénario en échec.
- Vérifie les resources liées et les opérations de lifecycle.
- Documente le résultat.

Focalise-toi sur le comportement réel du provider plutôt que sur la création de tests unitaires. Les tests unitaires Go sont optionnels uniquement quand ils apportent une valeur ajoutée à un fix.

# 7. Git et GitHub Pull Request

- Vérifie remote Git, branche courante et identité configurée.
- Utilise l'identité GitHub correcte (`github.com` : `k9fr4n <franck.sallet@gmail.com>` — vérifie avec `git remote -v` et `git config user.name user.email`).
- Crée une branche dédiée.
- Garde des changements ciblés sur les fixes provider et les tests d'acceptance HCL.
- Ne commit jamais credentials, secrets, fichiers de state Terraform ou artefacts temporaires.
- Commit avec des messages clairs.
- Push la branche.
- Crée une Pull Request vers la branche par défaut appropriée.
- Inclus bugs découverts, fixes implémentés, scénarios de test et résultats d'exécution réels dans la description de la PR.

Ne force-push jamais et n'écrase jamais du travail sans rapport.

# 8. Sécurité

- Utilise exclusivement LAB 201 et LAB 203 pour cette campagne.
- Ne cible jamais des systèmes de production.
- Préserve les configurations `.tf` existantes et les changements utilisateur.
- Évite toute modification destructive de domaine, firewall, réseau, routage ou service critique sans autorisation explicite.
- Utilise des fichiers de state isolés.
- Nettoie les resources créées par les tests.
- N'expose jamais credentials ou secrets.
- Documente les tests dangereux ou impossibles au lieu de les exécuter.

# 9. Livrables

- Configurations HCL étendues pour CHAQUE resource et data source.
- Build réussi du provider.
- Résultats réels d'exécution Terraform CLI depuis LAB 201 contre LAB 203.
- Bugs reproduits et corrigés.
- Scénarios de régression.
- Vérification du state Terraform et de l'idempotence.
- Rapport Markdown avec findings, sévérité, étapes de reproduction, fixes et limitations restantes.
- Commits Git et URL de Pull Request GitHub.

**Objectif final :** travaille de façon autonome de la découverte jusqu'à la création de la PR. Pousse le provider à ses limites avec de vraies opérations Terraform CLI. Priorise sécurité, lifecycle, cohérence du state, idempotence et fiabilité.

Ne prétends jamais qu'un test est passé sans l'avoir réellement exécuté. N'invente jamais de bugs ni de résultats de tests. Si un test ne peut pas être exécuté, explique clairement pourquoi.
