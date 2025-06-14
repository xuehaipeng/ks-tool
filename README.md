# ks-tool

A command-line tool for executing commands and copying files to groups of remote hosts via SSH.

## Features

- Execute shell commands on multiple remote hosts as root user
- Copy files to multiple remote hosts via SCP as root user
- Organize hosts into groups for easy management
- Support for different SSH configurations per host (username, password, sudo password, port)
- Concurrent execution for better performance
- Detailed logging using klog

## Installation

```bash
git clone https://github.com/xuehaipeng/ks-tool.git
cd ks-tool
go build -o ks-tool
```

## Configuration

Create a `hosts.yaml` file to define your host groups:

```yaml
groups:
  - name: web-servers
    hosts:
      - ip: 192.168.1.10
        username: admin
        password: password123
        sudo_password: sudopass123
        port: 22
      - ip: 192.168.1.11
        username: admin
        password: password123
        sudo_password: sudopass123
        port: 22
  
  - name: database-servers
    hosts:
      - ip: 192.168.1.20
        username: dbadmin
        password: dbpass123
        sudo_password: dbsudo123
        port: 22
```

### Configuration Fields

- `ip`: IP address of the remote host
- `username`: SSH username
- `password`: SSH password
- `sudo_password`: Password for sudo commands (optional)
- `port`: SSH port (default: 22)

## Usage

### Execute Commands

Execute a command on specific host groups:

```bash
# Execute command on web-servers group
./ks-tool exec "ls -la /var/log" --groups web-servers

# Execute command on multiple groups
./ks-tool exec "systemctl status nginx" --groups web-servers,app-servers

# Use custom config file
./ks-tool exec "uptime" --groups web-servers --config my-hosts.yaml
```

### Copy Files

Copy files to remote hosts via SCP:

```bash
# Copy file to web-servers group
./ks-tool scp /local/path/to/file.txt --groups web-servers --remote-path /remote/path/file.txt

# Copy to multiple groups
./ks-tool scp script.sh --groups web-servers,app-servers --remote-path /tmp/script.sh
```

### Command Line Options

Global options:
- `--config, -c`: Path to hosts configuration file (default: hosts.yaml)
- `--v`: Log verbosity level for klog

Exec command options:
- `--groups, -g`: Host groups to execute command on (required)

SCP command options:
- `--groups, -g`: Host groups to copy file to (required)
- `--remote-path, -r`: Remote path to copy file to (required)

### Logging

The tool uses klog for logging. You can control log verbosity:

```bash
# Basic logging
./ks-tool exec "hostname" --groups web-servers

# Verbose logging
./ks-tool exec "hostname" --groups web-servers --v=2

# Debug logging
./ks-tool exec "hostname" --groups web-servers --v=4
```

## Examples

```bash
# Check disk usage on all web servers
./ks-tool exec "df -h" --groups web-servers

# Restart nginx on web servers
./ks-tool exec "systemctl restart nginx" --groups web-servers

# Deploy a script to app servers
./ks-tool scp deploy.sh --groups app-servers --remote-path /tmp/deploy.sh

# Execute the deployed script
./ks-tool exec "chmod +x /tmp/deploy.sh && /tmp/deploy.sh" --groups app-servers

# Update package lists on multiple groups
./ks-tool exec "apt update" --groups web-servers,database-servers,app-servers
```

## Security Notes

- The tool stores passwords in plain text in the configuration file
- Consider using SSH keys instead of passwords for better security
- Ensure your configuration file has appropriate permissions (e.g., `chmod 600 hosts.yaml`)
- The tool executes commands as root using sudo

## Building

```bash
# Build for current platform
go build -o ks-tool

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o ks-tool-linux

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o ks-tool.exe
``` 