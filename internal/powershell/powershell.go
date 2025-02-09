package powershell

import (
	"bytes"
	"log"

	"golang.org/x/crypto/ssh"
)

func ExecutePowerShellCommand(client *ssh.Client, command string) (string, error) {
	log.Printf("[DEBUG] Creating new SSH session")
	session, err := client.NewSession()
	if err != nil {
		log.Printf("[ERROR] Failed to create SSH session: %v", err)
		return "", err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	log.Printf("[DEBUG] Executing PowerShell command: %s", command)
	err = session.Run("powershell -Command " + command)
	if err != nil {
		log.Printf("[ERROR] Failed to run PowerShell command: %v", err)
		return "", err
	}

	output := b.String()
	log.Printf("[DEBUG] Command output: %s", output)
	return output, nil
}
