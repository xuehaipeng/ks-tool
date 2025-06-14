package ssh

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/xuehaipeng/ks-tool/pkg/config"
	"golang.org/x/crypto/ssh"
	"k8s.io/klog/v2"
)

// Client represents an SSH client
type Client struct {
	client *ssh.Client
	host   config.Host
}

// NewClient creates a new SSH client
func NewClient(host config.Host) (*Client, error) {
	sshConfig := &ssh.ClientConfig{
		User: host.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(host.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	// Default port to 22 if not specified
	port := host.Port
	if port == 0 {
		port = 22
	}

	addr := fmt.Sprintf("%s:%d", host.IP, port)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", addr, err)
	}

	return &Client{
		client: client,
		host:   host,
	}, nil
}

// Close closes the SSH connection
func (c *Client) Close() error {
	return c.client.Close()
}

// ExecuteCommand executes a command on the remote host as root
func (c *Client) ExecuteCommand(command string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// If we have a sudo password, prefix the command with sudo
	if c.host.SudoPassword != "" {
		command = fmt.Sprintf("echo '%s' | sudo -S %s", c.host.SudoPassword, command)
	} else {
		command = fmt.Sprintf("sudo %s", command)
	}

	klog.V(2).Infof("Executing command on %s: %s", c.host.IP, command)

	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("command failed: %v", err)
	}

	return string(output), nil
}

// CopyFile copies a local file to the remote host
func (c *Client) CopyFile(localPath, remotePath string) error {
	// Open local file
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file %s: %v", localPath, err)
	}
	defer localFile.Close()

	// Get file info
	fileInfo, err := localFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}

	// Create SCP session
	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Create remote directory if needed
	remoteDir := filepath.Dir(remotePath)
	if remoteDir != "." {
		if err := c.createRemoteDir(remoteDir); err != nil {
			return fmt.Errorf("failed to create remote directory: %v", err)
		}
	}

	// Prepare SCP command
	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()

		// Send file header
		fmt.Fprintf(w, "C%#o %d %s\n", fileInfo.Mode().Perm(), fileInfo.Size(), filepath.Base(remotePath))

		// Send file content
		io.Copy(w, localFile)

		// Send end-of-file marker
		fmt.Fprint(w, "\x00")
	}()

	// Run SCP command
	scpCmd := fmt.Sprintf("scp -t %s", remotePath)
	if c.host.SudoPassword != "" {
		scpCmd = fmt.Sprintf("echo '%s' | sudo -S %s", c.host.SudoPassword, scpCmd)
	} else {
		scpCmd = fmt.Sprintf("sudo %s", scpCmd)
	}

	klog.V(2).Infof("Copying file to %s: %s -> %s", c.host.IP, localPath, remotePath)

	if err := session.Run(scpCmd); err != nil {
		return fmt.Errorf("SCP failed: %v", err)
	}

	return nil
}

// createRemoteDir creates a directory on the remote host
func (c *Client) createRemoteDir(remotePath string) error {
	cmd := fmt.Sprintf("mkdir -p %s", remotePath)
	_, err := c.ExecuteCommand(cmd)
	return err
}
