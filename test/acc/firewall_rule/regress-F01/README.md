# Regression F01 — plage mono-port degeneree `55014-55014`

## Contexte

Finding F01 (run `2611210137`, scenario `01-inputs-port-bounds`, tentative 1) :
`local_port = ["1", "65535", "55011-55013", "55014-55014"]` passe le
`firewallPortValidator` mais Windows normalise la plage degeneree
`55014-55014` en port simple `55014`. Le `Create` retourne l'etat relu
(`Read`) tel quel, Terraform leve `inconsistent result after apply`
(`.local_port[3]: was "55014-55014", but now "55014"`), l'apply sort en
exit 1 et la regle reste orpheline sur 203 (etat tainte/vide, nettoyage
manuel via `Remove-NetFirewallRule`).

Reproduit a l'identique avec la config minimale `repro/F01` (run
`2611210137`) : apply exit 1, meme message, regle `tfacc-2611210137-rf01`
creee sur 203 puis nettoyee (`REMAINING:0` verifie sur 203).

## Cause (sans modification de code — piste pour `provider-coder`)

- `firewallPortValidator` (`internal/provider/resource_windows_firewall_rule.go`,
  lignes ~868-913) accepte `55014-55014` (borne 0-65535, `lo <= hi`).
- `modelToFirewallInput` (lignes ~677-720) transmet la valeur brute, puis
  `buildFirewallParams` (`internal/winclient/firewall_rule.go`, lignes
  ~327-329) l'injecte telle quelle dans `New-NetFirewallRule`.
- Aucune normalisation de ports cote lecture : `normaliseStrArr`
  (`firewall_rule.go`, lignes ~405-410) ne gere que le cas vide (`["Any"]`),
  contrairement aux adresses qui ont `normaliseFirewallAddress`
  (lignes ~418-449).

Correction suggeree : canonicaliser plan-side la plage degeneree `X-X`
en port simple `X` (dans `modelToFirewallInput` ou via un plan modifier),
ou a defaut rejeter `X-X` dans `firewallPortValidator` avec un diagnostic
`Invalid port value` plan-time (moins bon : valeur pourtant legitime
cote Windows).

## Etapes de reproduction (LAB 201 -> LAB 203)

Les commandes Terraform s'executent sur 201 avec `TF_CLI_CONFIG_FILE`
pointe sur le `terraform.rc` du run (dev_override vers le binaire provider
du run), en suivant la procedure `acc/lab-runner`.
Le prefixe est parametrable via `-var rule_prefix=...` (defaut `tfacc`).

1. `terraform init -input=false -no-color` — attendu : exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — attendu
   **apres correction : exit 0**. Avant correction : exit 1
   (`inconsistent result after apply`, `.local_port[0]`).
3. `terraform plan -detailed-exitcode -input=false -no-color` — attendu :
   exit 0 (`No changes`, aucune perpetual diff port).
4. Verification sur 203 :
   `Get-NetFirewallRule -Name '<prefix>-regress-f01' | Get-NetFirewallPortFilter`
   montre `LocalPort = 55014`.
5. `terraform destroy -auto-approve -input=false -no-color` — attendu : exit 0.
6. Verification sur 203 : regle absente, aucun residu `<prefix>-regress-f01`.

## Attendu

- Apply puis plan vide avec `local_port = ["55014-55014"]` (ou la forme
  canonicalisee par le fix, documentee ici si le fix change la config).
- Aucun secret dans ce scenario, aucun fichier d'etat versionne.
