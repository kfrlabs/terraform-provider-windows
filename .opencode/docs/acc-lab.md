# Lab d'acceptance Terraform : LAB 201 → LAB 203

Référence partagée par `/terraform/acc-resource` et les subagents `acc/*`. Lis ce fichier avant toute action sur le lab.

## Machines

| Rôle | Hôte | Détails |
|---|---|---|
| Contrôleur Terraform | LAB 201 — `172.18.122.201` (`LAB-WINDOCKER-01`) | Terraform `C:\Ecritel\Tools\terraform\terraform.exe` (dans le PATH). **Go absent** : on ne compile jamais sur 201. |
| Cible managée | LAB 203 — `172.18.122.203` (Windows Server 2025, PowerShell 5.1) | Joignable depuis 201 en SSH (port 22). |

LAB 201 est exclusivement le contrôleur, LAB 203 exclusivement la cible. Ne jamais inverser les rôles.

Accès depuis OpenChamber (compte `adminlocalecritel`, authentification par clé déjà en place) :

```bash
ssh -o BatchMode=yes adminlocalecritel@172.18.122.201 'powershell -NoProfile -Command "..."'
ssh -o BatchMode=yes adminlocalecritel@172.18.122.203 'powershell -NoProfile -Command "..."'
```

Ne jamais demander de mot de passe ni de clé privée en chat, ne jamais désactiver la vérification de host key.

## Bloc provider des scénarios (exécutés sur 201, ciblant 203)

```hcl
terraform {
  required_providers {
    windows = { source = "kfrlabs/windows" }
  }
}

provider "windows" {
  host             = "172.18.122.203"
  port             = 22
  username         = "adminlocalecritel"
  private_key_path = "C:/Users/adminlocalecritel/.ssh/id_lab203_rsa"
}
```

Les secrets éventuels (mots de passe de comptes de test) passent par `TF_VAR_*` dans l'environnement de la session PowerShell, jamais dans un fichier `.tf`, un log ou un argument `-var`.

## Build du provider (local, Docker, cross-compilation)

Go n'est installé ni dans OpenChamber ni sur 201 : on compile dans un conteneur `golang` sur le démon Docker local. Le chemin de bind mount est celui de l'**hôte Docker** :

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v /home/kfr/docker/openchamber/workspaces/terraform-provider-windows:/src -w /src \
  -e GOOS=windows -e GOARCH=amd64 -e CGO_ENABLED=0 \
  -e GOCACHE=/src/.gocache -e GOMODCACHE=/src/.gomodcache \
  golang:1.26 go build -buildvcs=false -o /src/dist/acc/terraform-provider-windows.exe .
```

Même image (sans `GOOS`/`GOARCH`) pour `go build ./...`, `go vet ./...`, `gofmt -l .` et `go test -short ./...`. `dist/`, `.gocache/` et `.gomodcache/` sont gitignorés.

## Arborescence d'un run

`<r>` = nom de la resource sans `windows_` ; `<run_id>` = `date -u +%y%m%d%H%M`.

| Local (gitignoré) `WORK_DIR=work/acc/<r>/<run_id>/` | LAB 201 `LAB_DIR=C:\lab\terraform-windows-test\acc\<r>\<run_id>\` |
|---|---|
| `scenarios.yaml`, `scenarios/<id>/*.tf` | `<id>\*.tf` + state isolé du scénario |
| `run_report.yaml`, `findings.yaml`, `REPORT.md`, `logs/` | `bin\terraform-provider-windows.exe`, `terraform.rc`, `logs\` |

Upload : `scp -q -o BatchMode=yes <fichier> "adminlocalecritel@172.18.122.201:C:/lab/terraform-windows-test/acc/<r>/<run_id>/bin/"` (créer les dossiers d'abord avec `New-Item -ItemType Directory -Force`). `scp -r` pour un dossier de scénario.

`LAB_DIR\terraform.rc` :

```hcl
provider_installation {
  dev_overrides {
    "kfrlabs/windows" = "C:/lab/terraform-windows-test/acc/<r>/<run_id>/bin"
  }
  direct {}
}
```

Chaque commande Terraform s'exécute ainsi, et l'exit code est toujours capturé :

```powershell
$env:TF_CLI_CONFIG_FILE = 'C:\lab\terraform-windows-test\acc\<r>\<run_id>\terraform.rc'
terraform -chdir='<LAB_DIR>\<id>' plan -input=false -no-color *> '<LAB_DIR>\logs\<id>-<n>-plan.log'; $LASTEXITCODE
```

Utilise `plan -detailed-exitcode` pour l'idempotence (0 = aucun changement, 2 = diff, 1 = erreur).

## Règles du lab (non négociables)

- Ne touche **jamais** aux fichiers à la racine de `C:\lab\terraform-windows-test` (binaire provider partagé, `terraform.tfstate`, `terraform.tfvars`, `.tf` existants) ni aux autres dossiers de campagnes : tout se passe sous `acc\<r>\<run_id>\`.
- Tout objet Windows créé porte le préfixe `tfacc-<run_id>` (ou `tfacc<run_id>` quand le nom n'accepte pas `-`), pour un nettoyage ciblé et sûr.
- Ne jamais viser l'interface MGMT (`172.18.122.203`) avec `dns_client`, `net_ip_address` ou `net_route` : interface `TEST` uniquement.
- Jamais d'écriture via `hostname`, `domain_membership`, `disk`, `partition` ou `volume` sans autorisation explicite de l'utilisateur : ces scénarios sont documentés `risk: forbidden` et non exécutés.
- Singletons (`timezone`, `ntp`, `power_plan`, `eventlog`, `firewall_profile`, …) : toujours `restore_on_destroy = true` quand l'attribut existe, et vérifier l'état d'origine après destroy.
- Pas de modification destructive de domaine, firewall, réseau, routage ou service critique.
- Horloge de 203 décalée d'environ +7 h (cosmétique, ex. `install_date`). Les téléchargements `http://` non TLS échouent depuis 203.
- Ne jamais déclarer un test réussi sans exécution réelle ; `terraform validate` seul ne prouve rien.
