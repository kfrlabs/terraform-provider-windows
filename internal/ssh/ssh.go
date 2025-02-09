package ssh

import (
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func CreateSSHClient(host, username, password, keyPath string, useSSHAgent bool) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	if useSSHAgent {
		if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		} else {
			log.Printf("[WARN] Failed to connect to SSH agent: %v", err)
		}
	}

	if keyPath != "" {
		key, err := ioutil.ReadFile(keyPath)
		if err != nil {
			log.Printf("[ERROR] Failed to read private key: %v", err)
			return nil, err
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			log.Printf("[ERROR] Failed to parse private key: %v", err)
			return nil, err
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else {
		authMethods = append(authMethods, ssh.Password(password))
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // À remplacer par une méthode sécurisée en production
		Timeout:         30 * time.Second,
	}

	conn, err := ssh.Dial("tcp", net.JoinHostPort(host, "22"), config)
	if err != nil {
		log.Printf("[ERROR] Failed to dial SSH: %v", err)
		return nil, err
	}

	return conn, nil
}
