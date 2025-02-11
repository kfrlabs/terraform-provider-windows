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
		log.Printf("[DEBUG] Attempting to connect to SSH agent")
		if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
			log.Printf("[DEBUG] Successfully connected to SSH agent")
		} else {
			log.Printf("[WARN] Failed to connect to SSH agent: %v", err)
		}
	}

	if keyPath != "" {
		log.Printf("[DEBUG] Reading private key from path: %s", keyPath)
		key, err := ioutil.ReadFile(keyPath)
		if err != nil {
			log.Printf("[ERROR] Failed to read private key: %v", err)
			return nil, err
		}

		log.Printf("[DEBUG] Parsing private key")
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			log.Printf("[ERROR] Failed to parse private key: %v", err)
			return nil, err
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else {
		log.Printf("[DEBUG] Using password authentication")
		authMethods = append(authMethods, ssh.Password(password))
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // À remplacer par une méthode sécurisée en production
		Timeout:         30 * time.Second,
	}

	log.Printf("[DEBUG] Dialing SSH server at host: %s", host)
	conn, err := ssh.Dial("tcp", net.JoinHostPort(host, "22"), config)
	if err != nil {
		log.Printf("[ERROR] Failed to dial SSH: %v", err)
		return nil, err
	}

	log.Printf("[DEBUG] Successfully created SSH client")
	return conn, nil
}
