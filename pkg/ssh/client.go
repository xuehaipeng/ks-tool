package ssh

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

	// Wrap the entire command in a shell to properly handle pipelines, redirections, etc.
	// This ensures that complex commands like "lscpu | grep 'Model name'" work correctly
	var fullCommand string
	if c.host.SudoPassword != "" {
		// Use sudo with password and execute the command in a shell
		fullCommand = fmt.Sprintf("echo '%s' | sudo -S sh -c %s", c.host.SudoPassword, shellQuote(command))
	} else {
		// Use sudo without password and execute the command in a shell
		fullCommand = fmt.Sprintf("sudo sh -c %s", shellQuote(command))
	}

	klog.V(2).Infof("Executing command on %s: %s", c.host.IP, fullCommand)

	output, err := session.CombinedOutput(fullCommand)
	if err != nil {
		return string(output), fmt.Errorf("command failed: %v", err)
	}

	return string(output), nil
}

// shellQuote properly quotes a command for shell execution
func shellQuote(command string) string {
	// Use single quotes to prevent shell interpretation of special characters
	// Replace any single quotes in the command with '\''
	escaped := strings.ReplaceAll(command, "'", "'\"'\"'")
	return fmt.Sprintf("'%s'", escaped)
}

// CopyPath copies a local file or directory to the remote host
// If localPath is a directory, it will be copied recursively
func (c *Client) CopyPath(localPath, remotePath string) error {
	// Get file info to determine if it's a file or directory
	fileInfo, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("failed to stat local path %s: %v", localPath, err)
	}

	if fileInfo.IsDir() {
		return c.copyDirectory(localPath, remotePath)
	} else {
		return c.CopyFile(localPath, remotePath)
	}
}

// copyDirectory recursively copies a directory to the remote host
func (c *Client) copyDirectory(localDir, remoteDir string) error {
	klog.V(2).Infof("Copying directory to %s: %s -> %s", c.host.IP, localDir, remoteDir)

	// Create the remote directory first
	if err := c.createRemoteDir(remoteDir); err != nil {
		return fmt.Errorf("failed to create remote directory %s: %v", remoteDir, err)
	}

	// Walk through the local directory
	return filepath.Walk(localDir, func(localPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Calculate relative path from the source directory
		relPath, err := filepath.Rel(localDir, localPath)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %v", err)
		}

		// Skip the root directory itself
		if relPath == "." {
			return nil
		}

		// Construct remote path
		remotePath := filepath.Join(remoteDir, relPath)
		// Convert to forward slashes for remote Unix systems
		remotePath = strings.ReplaceAll(remotePath, "\\", "/")

		if info.IsDir() {
			// Create remote directory
			klog.V(3).Infof("Creating remote directory: %s", remotePath)
			return c.createRemoteDir(remotePath)
		} else {
			// Copy file
			klog.V(3).Infof("Copying file: %s -> %s", localPath, remotePath)
			return c.CopyFile(localPath, remotePath)
		}
	})
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

	// Read file content
	fileContent, err := io.ReadAll(localFile)
	if err != nil {
		return fmt.Errorf("failed to read file content: %v", err)
	}

	// Create remote directory if needed
	remoteDir := filepath.Dir(remotePath)
	if remoteDir != "." && remoteDir != "/" {
		if err := c.createRemoteDir(remoteDir); err != nil {
			return fmt.Errorf("failed to create remote directory: %v", err)
		}
	}

	klog.V(2).Infof("Copying file to %s: %s -> %s", c.host.IP, localPath, remotePath)

	// Create the file using cat command with proper escaping
	return c.createRemoteFile(remotePath, fileContent, fileInfo.Mode().Perm())
}

// createRemoteDir creates a directory on the remote host
func (c *Client) createRemoteDir(remotePath string) error {
	cmd := fmt.Sprintf("mkdir -p %s", remotePath)
	_, err := c.ExecuteCommand(cmd)
	return err
}

// createRemoteFile creates a file on the remote host with the given content
func (c *Client) createRemoteFile(remotePath string, content []byte, mode os.FileMode) error {
	// Use base64 encoding to safely transfer binary content
	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Create a temporary file and write content to it, then move to final location
	tempFile := fmt.Sprintf("/tmp/ks-temp-%d", time.Now().UnixNano())

	// Get stdin pipe
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %v", err)
	}

	// Prepare command to read from stdin and write to temp file, then move to final location
	var cmd string
	if c.host.SudoPassword != "" {
		cmd = fmt.Sprintf("echo '%s' | sudo -S sh -c 'cat > %s && mv %s %s && chmod %o %s'",
			c.host.SudoPassword, tempFile, tempFile, remotePath, mode, remotePath)
	} else {
		cmd = fmt.Sprintf("sudo sh -c 'cat > %s && mv %s %s && chmod %o %s'",
			tempFile, tempFile, remotePath, mode, remotePath)
	}

	// Start the command
	go func() {
		defer stdin.Close()
		stdin.Write(content)
	}()

	klog.V(3).Infof("Creating remote file with command: %s", cmd)

	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to create remote file: %v", err)
	}

	return nil
}
