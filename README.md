# ks-tool

A command-line tool for executing commands and copying files to groups of remote hosts via SSH.

## Features

- Execute shell commands on multiple remote hosts as root user
- Copy files to multiple remote hosts via SCP as root user
- Extract SSH information from Ansible inventory files and convert to hosts.yaml format
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

Create a `hosts.yaml` file to define your host groups. The tool supports two configuration formats:

### Group-Level Credentials (Recommended)

For groups where hosts share the same credentials:

```yaml
groups:
  - name: web-servers
    hosts:
      - ip: 192.168.1.10
      - ip: 192.168.1.11
    username: admin
    password: password123
    sudo_password: sudopass123
    port: 22
```

### Individual Host Credentials

For groups where each host has different credentials:

```yaml
groups:
  - name: database-servers
    hosts:
      - ip: 192.168.1.20
        username: dbadmin
        password: dbpass123
        sudo_password: dbsudo123
        port: 22
      - ip: 192.168.1.21
        username: dbadmin2
        password: dbpass456
        sudo_password: dbsudo456
        port: 2222
```

### Mixed Configuration

You can also mix both approaches - define group-level defaults and override them for specific hosts:

```yaml
groups:
  - name: mixed-servers
    hosts:
      - ip: 192.168.1.30
        # This host inherits all group credentials
      - ip: 192.168.1.31
        # This host overrides only the sudo password
        sudo_password: different_sudo_pass
    username: mixeduser
    password: mixedpass123
    sudo_password: mixedsudo123
    port: 22
```

### Configuration Fields

**Group Level:**
- `name`: Group name (required)
- `hosts`: List of hosts in the group (required)
- `username`: Default SSH username for all hosts in group
- `password`: Default SSH password for all hosts in group
- `sudo_password`: Default sudo password for all hosts in group (optional)
- `port`: Default SSH port for all hosts in group (default: 22)

**Host Level:**
- `ip`: IP address of the remote host (required)
- `username`: SSH username (overrides group username if specified)
- `password`: SSH password (overrides group password if specified)
- `sudo_password`: Sudo password (overrides group sudo_password if specified)
- `port`: SSH port (overrides group port if specified, default: 22)

## Usage

### Execute Commands

Execute a command on specific host groups. Supports complex shell operations including pipelines, redirections, and command chaining:

```bash
# Execute command on web-servers group
./ks exec "ls -la /var/log" --groups web-servers

# Pipeline operations
./ks exec "lscpu | grep 'Model name'" --groups web-servers
./ks exec "ps aux | grep nginx | wc -l" --groups web-servers

# Command chaining and redirections
./ks exec "df -h > /tmp/disk_usage.txt && cat /tmp/disk_usage.txt" --groups web-servers

# Execute command on multiple groups
./ks exec "systemctl status nginx" --groups web-servers,app-servers

# Use custom config file
./ks exec "uptime" --groups web-servers --config my-hosts.yaml
```

### Copy Files

Copy files to remote hosts via SCP:

```bash
# Copy file to web-servers group
./ks scp /local/path/to/file.txt --groups web-servers --remote-path /remote/path/file.txt

# Copy to multiple groups
./ks scp script.sh --groups web-servers,app-servers --remote-path /tmp/script.sh
```

### Extract Ansible Inventory

Convert Ansible inventory files to hosts.yaml format:

```bash
# Extract SSH information from Ansible inventory
./ks extract -i /path/to/ansible/inventory -o hosts.yaml

# Extract to custom output file
./ks extract --input inventory.ini --output my-hosts.yaml
```

The extract command will:
- Parse all host groups from the Ansible inventory
- Extract SSH configuration from `[all:vars]` section
- Handle host-specific SSH parameters (port, username, password)
- Skip special Ansible groups (add_*, del_*)
- Generate a hosts.yaml file compatible with ks-tool

### Command Line Options

Global options:
- `--config, -c`: Path to hosts configuration file (default: hosts.yaml)
- `--v`: Log verbosity level for klog

Exec command options:
- `--groups, -g`: Host groups to execute command on (required)

SCP command options:
- `--groups, -g`: Host groups to copy file to (required)
- `--remote-path, -r`: Remote path to copy file to (required)

Extract command options:
- `--input, -i`: Path to the Ansible inventory file (required)
- `--output, -o`: Path to the output hosts.yaml file (default: hosts.yaml)

### Logging

The tool uses klog for logging. You can control log verbosity:

```bash
# Basic logging
./ks exec "hostname" --groups web-servers

# Verbose logging
./ks exec "hostname" --groups web-servers --v=2

# Debug logging
./ks exec "hostname" --groups web-servers --v=4
```

## Examples

```bash
# Check disk usage on all web servers
./ks exec "df -h" --groups web-servers

# Pipeline operations to get CPU info
./ks exec "lscpu | grep 'Model name'" --groups web-servers

# Count running processes
./ks exec "ps aux | wc -l" --groups web-servers

# Restart nginx on web servers
./ks exec "systemctl restart nginx" --groups web-servers

# Deploy a script to app servers
./ks scp deploy.sh --groups app-servers --remote-path /tmp/deploy.sh

# Execute the deployed script with pipeline
./ks exec "chmod +x /tmp/deploy.sh && /tmp/deploy.sh | tee /tmp/deploy.log" --groups app-servers

# Update package lists on multiple groups
./ks exec "apt update" --groups web-servers,database-servers,app-servers

# Complex pipeline to check system resources
./ks exec "free -h && echo '---' && df -h | grep -v tmpfs" --groups web-servers

# Convert Ansible inventory to hosts.yaml
./ks extract -i /etc/ansible/inventory -o k8s-hosts.yaml

# Then use the converted hosts file for operations
./ks exec "kubectl get nodes" --groups kube_master --config k8s-hosts.yaml
```

## Security Notes

- The tool stores passwords in plain text in the configuration file
- Consider using SSH keys instead of passwords for better security
- Ensure your configuration file has appropriate permissions (e.g., `chmod 600 hosts.yaml`)
- The tool executes commands as root using sudo

## Building

### Using Makefile (Recommended)

```bash
# Build for current platform
make build

# Build for Linux (creates 'ks' binary)
make linux

# Build for Linux amd64 in build/ directory
make build-all

# Clean build artifacts
make clean

# Show all available targets
make help
```

### Manual Building

```bash
# Build for current platform
go build -o ks-tool

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o ks main.go

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o ks-tool.exe
``` 