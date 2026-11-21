# Regression F10 — le protocole IGMP n'a pas de mot-cle Windows

## Contexte

Finding F10 (run `2611210928`, scenario `01-inputs-protocol-aliases-f02`,
tentative 1) : avec le binaire du run (commit `1a09d3b`), `protocol = "2"`
et `protocol = "igmp"` echouent au Create avec `[invalid_input] The protocol
is invalid`, alors que le validateur `firewallProtocolValidator` les accepte
(mot-cle insensible a la casse + numeriques `0-255`).

Sondes directes sur 203 (New-NetFirewallRule, prefixe `tfacc-repro-*`,
nettoyees ensuite, `remaining=0`) :

- `-Protocol '2'` : accepte, `Get-NetFirewallPortFilter` renvoie `2`
  (verbatim, jamais `IGMP`) ;
- `-Protocol 'IGMP'` / `'igmp'` : rejete (`The protocol is invalid`) ;
- `-Protocol '58'` : accepte, renvoie `ICMPv6` ;
- `-Protocol 'Icmpv6'` / `'ICMPv6'` : accepte, renvoie `ICMPv6` ;
- `-Protocol '1'`/`'ICMPv4'`/`'6'`/`'TCP'`/`'17'`/`'UDP'` : acceptes,
  renvoient le mot-cle (`ICMPv4`, `TCP`, `UDP`).

Reproduit avec la config minimale `work/acc/firewall_rule/2611210928/repro/F10`
(binaire du run) : apply exit 1, `p2` (`"2"`) et `pigmp` (`"igmp"`) en
`invalid_input`, `p58` (`"58"`) et `picmpv6` (`"Icmpv6"`) crees sans erreur
(SemanticEquals OK), destroy exit 0, residus 0 sur 203.

## Cause (sans modification de code — piste pour `provider-coder`)

- `firewallProtocolNumericAlias` (`internal/winclient/firewall_rule.go`,
  lignes ~417-423) mappe `"2" -> "IGMP"`.
- `modelToFirewallInput`
  (`internal/provider/resource_windows_firewall_rule.go`, ligne ~863) puis
  `buildFirewallParams` (`internal/winclient/firewall_rule.go`, ligne ~334)
  envoient donc `Protocol = 'IGMP'` a `New-NetFirewallRule`, qui le rejette.
  Avant le fix F02, la valeur brute `"2"` etait envoyee et acceptee (c'est
  pourquoi le run 2611210928 passe `p2` avec l'ancien binaire partage
  `C:\lab\terraform-windows-test\terraform-provider-windows.exe`) : le
  mapping `"2" -> "IGMP"` est une regression pour ce cas.
- La forme canonique correcte du protocole 2 est le numerique `"2"`
  (c'est ce que Windows renvoie) : `"2"` doit rester `"2"`, et les mots-cles
  `"igmp"`/`"IGMP"` (insensibles a la casse) doivent se replier vers `"2"`
  avant l'envoi — le repli doit avoir lieu AVANT la boucle `EqualFold` sur
  les mots-cles de `CanonicalFirewallProtocol` (lignes ~431-442), sinon
  `"igmp"` se replie vers `"IGMP"` rejete.
- Verifier que `parseFirewallRuleState` (ligne ~590), `StringSemanticEquals`
  (`resource_windows_firewall_rule.go`, ~1394), `ModifyPlan` (~678) et CV-2
  restent coherents : tous passent par `CanonicalFirewallProtocol`, un seul
  point de correction (trace `trace_path` : 9 appelants inbound).
- Ne pas toucher aux autres alias (`1`->`ICMPv4`, `6`->`TCP`, `17`->`UDP`,
  `58`->`ICMPv6`, prouves acceptes par les sondes 203).

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE`
pointe sur le `terraform.rc` du run (dev_override vers le binaire provider
du run — ne pas utiliser le binaire partage racine), en suivant la procedure
`acc/lab-runner`. Le prefixe est parametrable via `-var rule_prefix=...`
(defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu
   **apres correction : exit 0** (4 added). Avant correction : exit 1
   (`two` et `igmp` en `invalid_input`, `fift8`/`mix` crees).
3. `terraform plan -detailed-exitcode -input=false -no-color` — attendu :
   exit 0 (`No changes`).
4. Verification sur 203 :
   `Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -like '<prefix>-regress-f10-*' }`
   puis `Get-NetFirewallPortFilter` : `two` et `igmp` en `2`, `fift8` et
   `mix` en `ICMPv6`.
5. `terraform destroy -auto-approve -input=false -no-color` — attendu : exit 0.
6. Verification sur 203 : aucune regle `<prefix>-regress-f10-*`, aucun residu.

## Attendu

- Apply puis plan vide avec les quatre formes (`2`, `igmp`, `58`, `Icmpv6`).
- Aucun secret dans ce scenario, aucun fichier d'etat versionne.
