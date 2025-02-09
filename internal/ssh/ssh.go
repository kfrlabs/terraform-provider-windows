package ssh

import (
	"io/ioutil"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func CreateSSHClient(host, username, password, keyPath string, useSSHAgent bool) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	// Ajouter l'authentification par agent SSH si demandé
	if useSSHAgent {
		if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		}
	}

	// Ajouter l'authentification par clé privée si un chemin est fourni
	if keyPath != "" {
		key, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, err
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else {
		// Ajouter l'authentification par mot de passe si aucune clé n'est fournie
		authMethods = append(authMethods, ssh.Password(password))
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	conn, err := ssh.Dial("tcp", net.JoinHostPort(host, "22"), config)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
