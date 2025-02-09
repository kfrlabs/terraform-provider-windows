# Build
go mod init github.com/FranckSallet/tf-windows
go get github.com/hashicorp/terraform-plugin-sdk/v2@v2.26.1
go get golang.org/x/crypto@v0.14.0
go mod tidy
go build -o ~/.terraform.d/plugins/local/FranckSallet/tf-windows/1.0.0/linux_amd64/terraform-provider-tf-windows

# struct
terraform-provider-tf-windows/
│
├── main.go                  # Point d'entrée principal pour le fournisseur Terraform
├── provider.go              # Déclaration du fournisseur et des ressources
│
├── internal/
│   ├── windows/
│   │   ├── feature.go       # Logique de gestion des fonctionnalités Windows
│   │   └── feature_test.go  # Tests pour la gestion des fonctionnalités Windows
│   │
│   ├── ssh/
│   │   ├── ssh.go           # Gestion de la connexion SSH
│   │   └── ssh_test.go      # Tests pour la connexion SSH
│   │
│   └── powershell/
│       ├── powershell.go    # Exécution des commandes PowerShell
│       └── powershell_test.go # Tests pour l'exécution des commandes PowerShell
│
├── go.mod                   # Fichier de module Go
└── go.sum                   # Fichier de somme de contrôle pour les dépendances Go
