# Regression F15 — CIDR avec bits d'hote canonises par Windows

## Contexte

Finding F15 (run `2611211023`, scenario `03-adv-maskform-output`,
tentative 1) : `remote_address = ["198.51.100.0/16", "2001:db8:2::/64"]`
echoue au Create avec `inconsistent result after apply` :

- `.remote_address[0]: was "198.51.100.0/16", but now "198.51.0.0/16"`.

La verification sur 203 a montre la regle malgre tout creee, avec
`RemoteAddress = {198.51.0.0/255.255.0.0, ...}` : Windows a canonise les
bits d'hote (`198.51.100.0/16` -> reseau `198.51.0.0`) et restitue la forme
masque pointille, que `normaliseFirewallAddress` convertit en `198.51.0.0/16`
sans canoniser le plan (`198.51.100.0/16`). `ListSemanticEquals` compare
alors index par index deux chaines differentes -> le core signale
l'incoherence. Le `local_address = ["203.0.113.0/24"]` (deja adresse
reseau, revenu `203.0.113.0/255.255.255.0` -> `203.0.113.0/24`) n'a pas
diverge et sert de temoin.

Preuve sans rejouage isole (lab 203 DOWN pendant le triage) : log
`logs/03-adv-maskform-output/03-adv-maskform-output-3-apply-step1.log`
(apply exit 1, message exact ci-dessus), verification 203 (`LocalAddress =
203.0.113.0/255.255.255.0`, `RemoteAddress = 198.51.0.0/255.255.0.0`),
puis destroy exit 0 et `0 residu tfacc-2611211023*` (`run_report.yaml`).

## Cause (sans modification de code — piste pour `provider-coder`)

- `CanonicalFirewallAddress` (`internal/winclient/firewall_rule.go`,
  ligne 483) ne replie que la casse de `Any` et les routes d'hote
  `/32`/`/128` (F11) : tout autre CIDR passe verbatim, bits d'hote inclus.
- `normaliseFirewallAddress` (lignes 557-579) convertit la notation masque
  vers CIDR (`198.51.0.0/255.255.0.0` -> `198.51.0.0/16`) en conservant
  l'adresse telle que Windows la renvoie (bits deja masques).
- Donc `Canonical(plan "198.51.100.0/16")` != `Canonical(etat
  "198.51.0.0/16")` et `ListSemanticEquals`
  (`resource_windows_firewall_rule.go`) renvoie faux -> `inconsistent
  result` au lieu d'un plan vide.
- Correction suggeree : dans `CanonicalFirewallAddress` (pour couvrir
  plan + etat + `ModifyPlan`/`foldFirewallListValue` d'un seul point),
  canoniser tout CIDR valide vers son adresse reseau via `net.ParseCIDR`
  (`ipNet.IP.String() + "/" + ones`), ex. `198.51.100.0/16` ->
  `198.51.0.0/16`. Ordre avec F11 : tester d'abord le repli `/32`->IP nue
  et `/128`->IP nue (deja en place, a conserver), puis le masquage reseau
  pour les autres premios. Ne pas toucher a `Any` (insensible a la casse),
  aux plages, aux noms (`LocalSubnet`, ...) ni a la conversion
  masque->CIDR. IPv6 : `net.ParseCIDR` masque aussi (`2001:db8:2:1::/64`
  -> `2001:db8:2::/64`) — meme traitement, sans casser regress-F03/F11.
- Cas limites a ne pas casser : `0.0.0.0/0`, `::/0`, `/32` et `/128`
  (regress-F11, repli IP nue, pas `x/32` -> reseau), `Any`, listes
  triees/dedup (regress-F03).

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE`
pointe sur le `terraform.rc` du run (dev_override vers le binaire provider
du run — ne pas utiliser le binaire partage racine), en suivant la procedure
`acc/lab-runner`. Le prefixe est parametrable via `-var rule_prefix=...`
(defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu
   **apres correction : exit 0** (1 added). Avant correction : exit 1
   (`main` en `inconsistent result`, `.remote_address[0]`).
3. `terraform plan -detailed-exitcode -input=false -no-color` — attendu :
   exit 0 (`No changes`).
4. Verification sur 203 : regle `<prefix>-regress-f15` presente,
   `LocalAddress = 203.0.113.0/255.255.255.0`,
   `RemoteAddress` contenant `198.51.0.0/255.255.0.0` (forme canonisee par
   Windows).
5. `terraform destroy -auto-approve -input=false -no-color` — attendu : exit 0.
6. Verification sur 203 : aucune regle `<prefix>-regress-f15*`, aucun residu.

## Attendu

- Apply puis plan vide avec un CIDR a bits d'hote : plan et etat se
  rejoignent sur l'adresse reseau canonique (`198.51.0.0/16`).
- Aucun secret dans ce scenario, aucun fichier d'etat versionne.
