# Regression F11 — suffixes d'hote /32 et /128 depouilles par Windows

## Contexte

Finding F11 (run `2611210928`, scenario `04-inputs-address-variants-canonical`,
tentative 1) : `local_address = ["192.0.2.1/32", "10.128.0.0/16", ...]`
echoue au Create avec `inconsistent result after apply`
(`[0]: was "192.0.2.1/32", now "10.128.0.0/16"`, `[1]`, `[2]`,
`element 4 has vanished`) alors que tri/dedup sont censes etre absorbes par
`firewallCanonicalListValue.ListSemanticEquals`.

Sondes directes sur 203 (prefixe `tfacc-repro-*`, nettoyees, `remaining=0`) :

- `-LocalAddress '192.0.2.1/32','10.128.0.0/16'` : renvoie
  `192.0.2.1 | 10.128.0.0/255.255.0.0` — le `/32` est depouille (IP nue),
  le `/16` revient en notation masque (convertie en CIDR par
  `normaliseFirewallAddress`, OK) ;
- `-LocalAddress '2001:db8:1::5/128','192.0.2.9'` : renvoie
  `192.0.2.9 | 2001:db8:1::5` — le `/128` est depouille lui aussi ;
- `-RemoteAddress '2001:db8:9::/64',...` : le `/64` est conserve tel quel
  (aucun repli `/64` a prevoir).

Reproduit avec la config minimale `work/acc/firewall_rule/2611210928/repro/F11`
(binaire du run) : apply exit 1, `host32` en `inconsistent result`
(`[0]`, `[1]`, etat trie `[10.128.0.0/16, 192.0.2.1]`), temoin `plain`
(sans `/32`) cree sans erreur, destroy exit 0, residus 0 sur 203.

## Cause (sans modification de code — piste pour `provider-coder`)

- `CanonicalFirewallAddress` (`internal/winclient/firewall_rule.go`,
  lignes ~469-475) ne replie que la casse de `Any` ; `normaliseFirewallAddress`
  (lignes ~527-552) ne convertit que la notation masque IPv4 vers CIDR.
  Ni l'un ni l'autre ne replie une route d'hote vers l'IP nue, donc
  `CanonicalFirewallAddressList(plan ["192.0.2.1/32", ...])` !=
  `CanonicalFirewallAddressList(etat ["192.0.2.1", ...])` et
  `ListSemanticEquals` (`resource_windows_firewall_rule.go`, ~1510) renvoie
  faux -> core compare index par index -> `inconsistent result`.
- Correction suggeree : dans `CanonicalFirewallAddress` (pour couvrir
  plan + etat + `ModifyPlan`/`foldFirewallListValue` d'un seul point),
  replier `a.b.c.d/32` (IPv4 valide) vers `a.b.c.d` et `.../128` (IPv6
  valide) vers l'adresse nue (via `net.ParseIP`, sans toucher aux autres
  CIDR ni a `Any`). Le `Read` renvoie deja la forme nue, les deux cotes
  deviennent egaux ; l'envoi (`buildFirewallParams`, ligne ~343) utilisera
  aussi la forme nue, acceptee par Windows (sondes).
- Cas limites a ne pas casser : `0.0.0.0/0`, `::/0`, CIDR `/16`/`/64`
  (regress-F03), `Any` insensible a la casse.

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE`
pointe sur le `terraform.rc` du run (dev_override vers le binaire provider
du run — ne pas utiliser le binaire partage racine), en suivant la procedure
`acc/lab-runner`. Le prefixe est parametrable via `-var rule_prefix=...`
(defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu
   **apres correction : exit 0** (2 added). Avant correction : exit 1
   (`host32` en `inconsistent result`, `host128` idem).
3. `terraform plan -detailed-exitcode -input=false -no-color` — attendu :
   exit 0 (`No changes`).
4. Verification sur 203 : `host32` en `192.0.2.1,10.128.0.0/16` (IP nue +
   CIDR), `host128` avec `2001:db8:1::5` nue.
5. `terraform destroy -auto-approve -input=false -no-color` — attendu : exit 0.
6. Verification sur 203 : aucune regle `<prefix>-regress-f11-*`, aucun residu.

## Attendu

- Apply puis plan vide avec suffixes `/32` et `/128` replies vers l'IP nue.
- Aucun secret dans ce scenario, aucun fichier d'etat versionne.
