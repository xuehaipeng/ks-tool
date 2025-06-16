# ks

A command-line tool for executing commands and copying files to groups of remote hosts via SSH.

## Features

- Execute shell commands on multiple remote hosts as root user
- Copy files and directories to multiple remote hosts via SCP as root user
- Extract SSH information from Ansible inventory files and convert to hosts.yaml format
- Generate kubelet certificates and kubeconfig files for Kubernetes nodes
- Organize hosts into groups for easy management
- Support for different SSH configurations per host (username, password, sudo password, port)
- Ad-hoc host support with smart credential lookup from configuration files
- Concurrent execution for better performance
- Support for complex shell operations (pipelines, redirections, command chaining)
- Automatic backup of critical system files during certificate generation
- Detailed logging using klog

## Installation

```bash
git clone https://github.com/xuehaipeng/ks-tool.git
cd ks-tool
make build  # Creates 'ks' binary for Linux
# or
go build -o ks main.go  # Build for current platform
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

Execute a command on specific host groups or individual hosts. Supports complex shell operations including pipelines, redirections, and command chaining:

```bash
# Execute command on web-servers group
ks exec "ls -la /var/log" --groups web-servers

# Pipeline operations
ks exec "lscpu | grep 'Model name'" --groups web-servers
ks exec "ps aux | grep nginx | wc -l" --groups web-servers

# Command chaining and redirections
ks exec "df -h > /tmp/disk_usage.txt && cat /tmp/disk_usage.txt" --groups web-servers

# Execute command on multiple groups
ks exec "systemctl status nginx" --groups web-servers,app-servers

# Execute on individual hosts (ad-hoc mode)
ks exec "uptime" --hosts 192.168.1.10,192.168.1.11 --user admin --pass password123

# Mix groups and individual hosts
ks exec "hostname" --groups web-servers --hosts 192.168.1.50 --user root

# Use custom config file
ks exec "uptime" --groups web-servers --config my-hosts.yaml
```

#### Ad-hoc Host Support

The tool supports executing commands on individual hosts without requiring them to be defined in a hosts.yaml file:

```bash
# Execute on single host with credentials
ks exec "df -h" --hosts 192.168.1.100 --user admin --pass mypassword --port 2222

# Execute on multiple hosts with same credentials
ks exec "systemctl status nginx" --hosts 192.168.1.10,192.168.1.11,192.168.1.12 --user root --pass rootpass

# Use sudo password for privilege escalation
ks exec "systemctl restart nginx" --hosts 192.168.1.10 --user admin --pass userpass --sudo-pass sudopass

# Smart credential lookup: if host exists in hosts.yaml, use those credentials
ks exec "uptime" --hosts 192.168.1.10 --user override_user  # Uses override_user but other creds from hosts.yaml
```

### Copy Files and Directories

Copy files or directories to remote hosts via SCP. Supports both group-based and ad-hoc host operations:

```bash
# Copy file to web-servers group
ks scp /local/path/to/file.txt --groups web-servers --remote-path /remote/path/file.txt

# Copy directory recursively to groups
ks scp ./config-dir --groups web-servers --remote-path /etc/myapp --recursive

# Copy to multiple groups
ks scp script.sh --groups web-servers,app-servers --remote-path /tmp/script.sh

# Copy directory to individual hosts (ad-hoc mode)
ks scp ./deploy --hosts 192.168.1.10 --user admin --pass password123 --remote-path /opt/deploy --recursive

# Copy to multiple individual hosts
ks scp config.conf --hosts 192.168.1.10,192.168.1.11 --user root --pass rootpass --remote-path /etc/myapp/config.conf

# Mix groups and individual hosts
ks scp script.sh --groups web-servers --hosts 192.168.1.50 --user admin --remote-path /tmp/script.sh
```

### Extract Ansible Inventory

Convert Ansible inventory files to hosts.yaml format:

```bash
# Extract SSH information from Ansible inventory
ks extract -i /path/to/ansible/inventory -o hosts.yaml

# Extract to custom output file
ks extract --input inventory.ini --output my-hosts.yaml
```

### Generate Kubelet Certificates and Kubeconfig Files

Generate kubelet certificates and kubeconfig files for Kubernetes nodes:

```bash
# Generate kubelet certificate and kubeconfig files for a node
ks gencert --hostname worker-1 --ip 192.168.1.100

# Generate with custom API server address
ks gencert --hostname master-1 --ip 10.0.1.10 --apiserver https://10.0.1.10:6443

# Generate with custom CA files
ks gencert --hostname master-1 --ip 10.0.1.10 --ca-file /path/to/ca.pem --ca-key-file /path/to/ca-key.pem

# Generate with custom output directory
ks gencert --hostname node-1 --ip 172.16.1.50 --output-dir /tmp/certs

# Generate with custom output files
ks gencert --hostname node-1 --ip 172.16.1.50 --cert-file /tmp/kubelet.pem --key-file /tmp/kubelet-key.pem --kubeconfig-file /tmp/kubelet.kubeconfig --kube-proxy-config-file /tmp/kube-proxy.kubeconfig

# Generate with custom certificate details
ks gencert --hostname node-1 --ip 192.168.1.10 --country US --state California --locality "San Francisco"
```

This command generates:
- Kubelet certificate (`kubelet.pem`) signed by the CA
- Kubelet private key (`kubelet-key.pem`)
- Kubelet kubeconfig file (`kubelet.kubeconfig`) with base64-encoded certificates
- Kube-proxy kubeconfig file (`kube-proxy.kubeconfig`) with base64-encoded certificates

Both kubeconfig files are ready to use and contain the proper authentication configuration for the Kubernetes cluster. The kubelet kubeconfig uses `system:node:hostname` as the user, while the kube-proxy kubeconfig uses `kube-proxy` as the user.

**Backup Functionality**: The command automatically backs up existing files if they are critical system files:
- `/etc/kubernetes/kubelet.kubeconfig` → `/etc/kubernetes/kubelet.kubeconfig.bak`
- `/etc/kubernetes/kube-proxy.kubeconfig` → `/etc/kubernetes/kube-proxy.kubeconfig.bak`
- `/etc/kubernetes/ssl/kubelet.pem` → `/etc/kubernetes/ssl/kubelet.pem.bak`
- `/etc/kubernetes/ssl/kubelet-key.pem` → `/etc/kubernetes/ssl/kubelet-key.pem.bak`

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
- `--groups, -g`: Host groups to execute command on (can be combined with --hosts)
- `--hosts, -H`: Individual hosts to execute command on (can be combined with --groups)
- `--user, -u`: SSH username for ad-hoc hosts
- `--pass, -p`: SSH password for ad-hoc hosts
- `--sudo-pass`: Sudo password for ad-hoc hosts
- `--port`: SSH port for ad-hoc hosts (default: 22)

SCP command options:
- `--groups, -g`: Host groups to copy file/directory to (can be combined with --hosts)
- `--hosts, -H`: Individual hosts to copy file/directory to (can be combined with --groups)
- `--remote-path, -r`: Remote path to copy file/directory to (required)
- `--recursive`: Copy directories recursively (default: true)
- `--user, -u`: SSH username for ad-hoc hosts
- `--pass, -p`: SSH password for ad-hoc hosts
- `--sudo-pass`: Sudo password for ad-hoc hosts
- `--port`: SSH port for ad-hoc hosts (default: 22)

Extract command options:
- `--input, -i`: Path to the Ansible inventory file (required)
- `--output, -o`: Path to the output hosts.yaml file (default: hosts.yaml)

GenCert command options:
- `--hostname`: Hostname of the target node (required)
- `--ip`: IP address of the target node (required)
- `--apiserver`: Kubernetes API server address (default: https://127.0.0.1:6443)
- `--ca-file`: Path to CA certificate file (default: /etc/kubernetes/ssl/ca.pem)
- `--ca-key-file`: Path to CA private key file (default: /etc/kubernetes/ssl/ca-key.pem)
- `--cert-file`: Output path for kubelet certificate (default: /etc/kubernetes/ssl/kubelet.pem)
- `--key-file`: Output path for kubelet private key (default: /etc/kubernetes/ssl/kubelet-key.pem)
- `--kubeconfig-file`: Output path for kubelet kubeconfig (default: /etc/kubernetes/kubelet.kubeconfig)
- `--kube-proxy-config-file`: Output path for kube-proxy kubeconfig (default: /etc/kubernetes/kube-proxy.kubeconfig)
- `--output-dir`: Output directory for generated files (overrides cert-file, key-file, and kubeconfig files)
- `--country`: Country name for certificate subject (default: CN)
- `--state`: State or province name for certificate subject (default: HangZhou)
- `--locality`: Locality name for certificate subject (default: XS)
- `--organization`: Organization name for certificate subject (default: system:nodes)
- `--org-unit`: Organizational unit for certificate subject (default: System)

### Logging

The tool uses klog for logging. You can control log verbosity:

```bash
# Basic logging
ks exec "hostname" --groups web-servers

# Verbose logging
ks exec "hostname" --groups web-servers --v=2

# Debug logging
ks exec "hostname" --groups web-servers --v=4
```

## Examples

```bash
# Check disk usage on all web servers
ks exec "df -h" --groups web-servers

# Pipeline operations to get CPU info
ks exec "lscpu | grep 'Model name'" --groups web-servers

# Count running processes
ks exec "ps aux | wc -l" --groups web-servers

# Restart nginx on web servers
ks exec "systemctl restart nginx" --groups web-servers

# Deploy a script to app servers
ks scp deploy.sh --groups app-servers --remote-path /tmp/deploy.sh

# Deploy entire directory structure
ks scp ./deployment-configs --groups app-servers --remote-path /opt/configs --recursive

# Execute the deployed script with pipeline
ks exec "chmod +x /tmp/deploy.sh && /tmp/deploy.sh | tee /tmp/deploy.log" --groups app-servers

# Update package lists on multiple groups
ks exec "apt update" --groups web-servers,database-servers,app-servers

# Complex pipeline to check system resources
ks exec "free -h && echo '---' && df -h | grep -v tmpfs" --groups web-servers

# Convert Ansible inventory to hosts.yaml
ks extract -i /etc/ansible/inventory -o k8s-hosts.yaml

# Generate kubelet certificates and kubeconfig files for new nodes
ks gencert --hostname worker-3 --ip 192.168.1.103 --apiserver https://192.168.1.100:6443 --output-dir /tmp/worker-3-certs

# Then use the converted hosts file for operations
ks exec "kubectl get nodes" --groups kube_master --config k8s-hosts.yaml
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
go build -o ks main.go

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o ks main.go

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o ks.exe main.go
``` 