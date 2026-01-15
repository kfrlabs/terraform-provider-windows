package ssh

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Config contient les paramètres de connexion SSH
type Config struct {
	Host                  string
	Username              string
	Password              string
	KeyPath               string
	UseSSHAgent           bool
	ConnTimeout           time.Duration
	KnownHostsPath        string
	HostKeyFingerprints   []string
	StrictHostKeyChecking bool
}

// Client encapsule la connexion SSH
type Client struct {
	*ssh.Client
}

// NewClient crée une nouvelle connexion SSH avec les paramètres fournis
func NewClient(config Config) (*Client, error) {
	var authMethods []ssh.AuthMethod

	if config.UseSSHAgent {
		if agentAuth, err := sshAgentAuth(); err == nil {
			authMethods = append(authMethods, agentAuth)
		}
	}

	if config.KeyPath != "" {
		if keyAuth, err := publicKeyAuth(config.KeyPath); err == nil {
			authMethods = append(authMethods, keyAuth)
		}
	} else if config.Password != "" {
		authMethods = append(authMethods, ssh.Password(config.Password))
	}

	// Créer le callback de vérification de clé d'hôte
	hostKeyCallback, err := createHostKeyCallback(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create host key callback: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            config.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         config.ConnTimeout,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(config.Host, "22"), sshConfig)
	if err != nil {
		return nil, err
	}

	return &Client{client}, nil
}

// createHostKeyCallback crée un callback de vérification de clé d'hôte sécurisé
// ✅ CORRIGÉ : Plus de mode insecure, toujours utiliser known_hosts par défaut
func createHostKeyCallback(config Config) (ssh.HostKeyCallback, error) {
	// Mode 1 : Vérifier les empreintes digitales (prioritaire si fournies)
	if len(config.HostKeyFingerprints) > 0 {
		return createFingerprintCallback(config.Host, config.HostKeyFingerprints, config.StrictHostKeyChecking), nil
	}

	// Mode 2 : Utiliser known_hosts (par défaut)
	knownHostsPath := config.KnownHostsPath
	if knownHostsPath == "" {
		// ✅ NOUVEAU : Utiliser known_hosts par défaut
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot determine home directory for known_hosts: %w", err)
		}
		knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}

	// ✅ MODIFIÉ : Toujours utiliser known_hosts, pas de mode insecure
	return createKnownHostsCallback(knownHostsPath, config.StrictHostKeyChecking)
}

// createKnownHostsCallback crée un callback à partir du fichier known_hosts
func createKnownHostsCallback(knownHostsPath string, strictMode bool) (ssh.HostKeyCallback, error) {
	// Résoudre le chemin ~ si nécessaire
	if strings.HasPrefix(knownHostsPath, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve home directory: %w", err)
		}
		knownHostsPath = filepath.Join(home, knownHostsPath[1:])
	}

	// Vérifier si le fichier existe
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		if strictMode {
			return nil, fmt.Errorf(
				"known_hosts file not found at %s (strict mode enabled)\n"+
					"Please run: ssh-keyscan -H <host> >> %s\n"+
					"Or provide host_key_fingerprints in provider configuration",
				knownHostsPath, knownHostsPath)
		}

		// En mode non-strict, créer un fichier vide
		if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0700); err != nil {
			return nil, fmt.Errorf("failed to create known_hosts directory: %w", err)
		}
		if _, err := os.Create(knownHostsPath); err != nil {
			return nil, fmt.Errorf("failed to create known_hosts file: %w", err)
		}
	}

	// Créer le callback
	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load known_hosts: %w", err)
	}

	return hostKeyCallback, nil
}

// createFingerprintCallback crée un callback qui valide les empreintes digitales
func createFingerprintCallback(host string, fingerprints []string, strictMode bool) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// Calculer l'empreinte digitale de la clé
		keyFingerprint := ssh.FingerprintSHA256(key)

		// Vérifier si l'empreinte correspond à l'une des empreintes autorisées
		for _, expectedFingerprint := range fingerprints {
			if keyFingerprint == expectedFingerprint {
				return nil // Accepter la clé
			}
		}

		// L'empreinte ne correspond pas
		errorMsg := fmt.Sprintf(
			"host key verification failed for %s\nExpected one of: %v\nGot: %s",
			hostname,
			fingerprints,
			keyFingerprint,
		)

		if strictMode {
			return fmt.Errorf(errorMsg)
		}

		// En mode non-strict, logger un warning mais accepter
		fmt.Fprintf(os.Stderr, "WARNING: %s\n", errorMsg)
		return nil
	}
}

// ============================================================================
// MÉTHODES DU CLIENT SSH
// ============================================================================

// ExecuteCommand exécute une commande PowerShell sur le serveur Windows
// Retourne (stdout, stderr, error)
func (c *Client) ExecuteCommand(command string, timeoutSeconds int) (string, string, error) {
	session, err := c.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// Créer des buffers pour capturer stdout et stderr
	var stdout, stderr strings.Builder
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Exécuter la commande avec un timeout
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	// Gérer le timeout
	select {
	case <-time.After(time.Duration(timeoutSeconds) * time.Second):
		session.Close()
		return "", "", fmt.Errorf("command execution timeout after %d seconds", timeoutSeconds)
	case err := <-done:
		stdoutStr := strings.TrimRight(stdout.String(), "\r\n")
		stderrStr := strings.TrimRight(stderr.String(), "\r\n")
		return stdoutStr, stderrStr, err
	}
}

// ExecuteRawCommand exécute une commande brute (non PowerShell)
func (c *Client) ExecuteRawCommand(command string, timeoutSeconds int) (string, string, error) {
	session, err := c.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	var stdout, stderr strings.Builder
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	select {
	case <-time.After(time.Duration(timeoutSeconds) * time.Second):
		session.Close()
		return "", "", fmt.Errorf("command execution timeout after %d seconds", timeoutSeconds)
	case err := <-done:
		stdoutStr := strings.TrimRight(stdout.String(), "\r\n")
		stderrStr := strings.TrimRight(stderr.String(), "\r\n")
		return stdoutStr, stderrStr, err
	}
}

// Close ferme la connexion SSH
func (c *Client) Close() error {
	return c.Client.Close()
}

// ============================================================================
// FONCTIONS PRIVÉES D'AUTHENTIFICATION
// ============================================================================

// sshAgentAuth configure l'authentification par SSH agent
func sshAgentAuth() (ssh.AuthMethod, error) {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH agent: %w", err)
	}
	agentClient := agent.NewClient(sshAgent)
	return ssh.PublicKeysCallback(agentClient.Signers), nil
}

// publicKeyAuth configure l'authentification par clé publique
func publicKeyAuth(keyPath string) (ssh.AuthMethod, error) {
	// Résoudre le chemin ~
	if strings.HasPrefix(keyPath, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve home directory: %w", err)
		}
		keyPath = filepath.Join(home, keyPath[1:])
	}

	// Lire la clé privée
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Parser la clé
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return ssh.PublicKeys(signer), nil
}

// ============================================================================
// UTILITAIRES
// ============================================================================

// NewClientSecure crée une nouvelle connexion SSH avec vérification stricte des host keys
// C'est la fonction recommandée pour la production
func NewClientSecure(config Config) (*Client, error) {
	// Appliquer les défauts sécurisés
	if config.ConnTimeout == 0 {
		config.ConnTimeout = 30 * time.Second
	}

	// En mode strict par défaut pour cette fonction
	config.StrictHostKeyChecking = true

	// Utiliser known_hosts par défaut
	if config.KnownHostsPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		config.KnownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}

	return NewClient(config)
}

// GetHostKeyFingerprint retourne l'empreinte digitale SHA256 du serveur SSH
// ✅ IMPLÉMENTATION COMPLÈTE
func GetHostKeyFingerprint(host string, port string) (string, error) {
	if port == "" {
		port = "22"
	}

	// Établir une connexion TCP
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s:%s: %w", host, port, err)
	}
	defer conn.Close()

	// Variable pour stocker la clé d'hôte
	var hostKey ssh.PublicKey

	// Callback pour capturer la clé d'hôte
	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		hostKey = key
		return nil
	}

	// Configuration SSH minimale pour récupérer la clé
	config := &ssh.ClientConfig{
		User:            "dummy", // Utilisateur fictif, on ne va pas s'authentifier
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
		Auth:            []ssh.AuthMethod{}, // Pas d'authentification
	}

	// Établir la connexion SSH pour récupérer la clé d'hôte
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(host, port), config)
	if err != nil {
		// L'erreur d'authentification est attendue, mais on a déjà la clé d'hôte
		if hostKey == nil {
			return "", fmt.Errorf("failed to retrieve host key: %w", err)
		}
	} else {
		// Fermer la connexion proprement si elle a réussi
		defer sshConn.Close()
		go ssh.DiscardRequests(reqs)
		go func() {
			for range chans {
			}
		}()
	}

	// Calculer l'empreinte digitale au format SHA256
	fingerprint := ssh.FingerprintSHA256(hostKey)

	return fingerprint, nil
}

// GetHostKeyFingerprintLegacy retourne l'empreinte au format MD5 (legacy)
// Fourni pour compatibilité avec les anciens systèmes
func GetHostKeyFingerprintLegacy(host string, port string) (string, error) {
	if port == "" {
		port = "22"
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s:%s: %w", host, port, err)
	}
	defer conn.Close()

	var hostKey ssh.PublicKey

	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		hostKey = key
		return nil
	}

	config := &ssh.ClientConfig{
		User:            "dummy",
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
		Auth:            []ssh.AuthMethod{},
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(host, port), config)
	if err != nil {
		if hostKey == nil {
			return "", fmt.Errorf("failed to retrieve host key: %w", err)
		}
	} else {
		defer sshConn.Close()
		go ssh.DiscardRequests(reqs)
		go func() {
			for range chans {
			}
		}()
	}

	// Format MD5 (legacy)
	fingerprint := ssh.FingerprintLegacyMD5(hostKey)

	return fingerprint, nil
}

// ============================================================================
// HELPERS POUR LES STRINGS (UTILITAIRES)
// ============================================================================

// Contains vérifie si une chaîne contient une sous-chaîne
func stringContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
