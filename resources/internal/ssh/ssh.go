package ssh

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/FranckSallet/tf-windows/resources/internal/powershell"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Config contient les paramètres de connexion SSH
type Config struct {
	Host        string
	Username    string
	Password    string
	KeyPath     string
	UseSSHAgent bool
	ConnTimeout time.Duration
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

	sshConfig := &ssh.ClientConfig{
		User:            config.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         config.ConnTimeout,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(config.Host, "22"), sshConfig)
	if err != nil {
		return nil, err
	}

	return &Client{client}, nil
}

// NewSession crée une nouvelle session SSH
func (c *Client) NewSession() (*ssh.Session, error) {
	return c.Client.NewSession()
}

// Close ferme la connexion SSH
func (c *Client) Close() error {
	return c.Client.Close()
}

func sshAgentAuth() (ssh.AuthMethod, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}

	agentClient := agent.NewClient(conn)
	return ssh.PublicKeysCallback(agentClient.Signers), nil
}

func publicKeyAuth(keyPath string) (ssh.AuthMethod, error) {
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(signer), nil
}

func (c *Client) ExecuteCommand(command string, timeout int) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	session, err := c.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %v", err)
	}
	defer session.Close()

	executor := powershell.NewExecutor(session, nil)
	_, _, err = executor.Execute(ctx, command)
	if err != nil {
		return fmt.Errorf("command error: %v", err)
	}

	return nil
}
