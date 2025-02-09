package powershell

import (
	"bytes"
	"log"

	"golang.org/x/crypto/ssh"
)

func ExecutePowerShellCommand(client *ssh.Client, command string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		log.Printf("[ERROR] Failed to create SSH session: %v", err)
		return "", err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	err = session.Run("powershell -Command " + command)
	if err != nil {
		log.Printf("[ERROR] Failed to run PowerShell command: %v", err)
		return "", err
	}

	return b.String(), nil
}
