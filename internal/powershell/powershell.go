package powershell

import (
	"bytes"

	"golang.org/x/crypto/ssh"
)

func ExecutePowerShellCommand(client *ssh.Client, command string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	err = session.Run("powershell -Command " + command)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}
