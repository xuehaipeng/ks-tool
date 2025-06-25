# Adding Kubernetes Nodes with ks Tool

## Background

This guide serves as a supplementary manual to the [kubeasz](https://github.com/easzlab/kubeasz) project, which provides automated Kubernetes cluster deployment using Ansible scripts. While kubeasz is an excellent tool for quickly deploying high-availability Kubernetes clusters, it currently supports only amd64 and arm64 architectures.

This manual operation guide fills the gap by providing step-by-step instructions for adding Kubernetes nodes to clusters that kubeasz might not support, such as:
- Alternative CPU architectures (e.g., LoongArch64, RISC-V, etc.)
- Custom Linux distributions not covered by kubeasz
- Environments where Ansible automation is not feasible
- Situations requiring manual control over the installation process

The guide leverages the `ks` tool for efficient remote operations, providing a middle ground between fully automated deployment and completely manual installation.

## Overview

This guide describes how to add new nodes to an existing Kubernetes cluster using the `ks` tool. The process involves installing containerd as the container runtime, deploying Kubernetes binaries, generating certificates, and configuring services.

## Prerequisites

- An existing Kubernetes cluster with at least one master node
- The `ks` tool installed and configured on the master node
- Required artifacts in the current directory:
  - `containerd-1.7.20-linux-loong64.tar.gz`
  - `kubernetes-node-linux-loong64.tar.gz`
  - Offline container images: `pause.tar.gz`, `flannel-loong64.tar.gz`, `flannel-cni-plugin-loong64.tar.gz`
  - Configuration files: `containerd_config.toml`, `containerd.service`, `kube-proxy.service`
  - Kubelet configuration: `kubelet_config.yaml`
  - System configuration: `/etc/sysctl.d/95-k8s-sysctl.conf` (from master node)
  - RBAC configuration: `node-rbac.yaml` (to be applied on master node)
  - **Note**: `kubelet.service` and `kube-proxy-config.yaml` are now generated automatically by the `ks gencert` command with node-specific hostname and IP settings

## Step 1: Apply Node RBAC Configuration

Before adding new nodes, apply the required RBAC configuration on the master node to ensure proper node permissions:

```bash
# Apply node RBAC configuration on the master node
kubectl apply -f node-rbac.yaml

# Verify the RBAC resources were created
kubectl get clusterrole system:node-lease-access
kubectl get clusterrolebinding system:node-lease-access-binding
```

The `node-rbac.yaml` file should contain:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:node-lease-access
rules:
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "create", "update", "patch", "delete"]
  - apiGroups: [ "storage.k8s.io" ]
    resources: [ "csinodes" ]
    verbs: [ "get", "list", "watch" ]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:node-lease-access-binding
subjects:
  - kind: Group
    name: system:nodes
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: system:node-lease-access
  apiGroup: rbac.authorization.k8s.io
```

## Step 2: Prepare Host Configuration

Create a `hosts.yaml` file for the new nodes:

```yaml
groups:
  - name: new-nodes
    hosts:
      - ip: 192.168.1.100  # Replace with actual node IP
        hostname: worker-1  # Replace with actual hostname
      - ip: 192.168.1.101  # Add more nodes as needed
        hostname: worker-2
    username: root
    password: your_password  # Replace with actual password
    port: 22
```

## Step 3: Configure System Prerequisites

### 3.1 Install Required Packages

Install essential packages required for Kubernetes nodes:

```bash
# Install packages using a smart detection script
ks exec 'if command -v yum >/dev/null 2>&1; then
    echo "Using YUM package manager"
    yum install -y conntrack socat ipset
elif command -v dnf >/dev/null 2>&1; then
    echo "Using DNF package manager"
    dnf install -y conntrack socat ipset
elif command -v apt >/dev/null 2>&1; then
    echo "Using APT package manager"
    apt update && apt install -y conntrack socat ipset
elif command -v zypper >/dev/null 2>&1; then
    echo "Using Zypper package manager"
    zypper install -y conntrack socat ipset
else
    echo "No supported package manager found"
    exit 1
fi' --groups new-nodes

# Verify package installation
ks exec "which conntrack && which socat && which ipset && echo 'All packages installed successfully'" --groups new-nodes
```

### 3.2 Configure System Settings

```bash
# Copy sysctl configuration file (recommended if file exists)
ks scp /etc/sysctl.d/95-k8s-sysctl.conf --groups new-nodes --remote-path /etc/sysctl.d/95-k8s-sysctl.conf

# Apply sysctl settings
ks exec "sysctl --system" --groups new-nodes
```

## Step 4: Extract and Prepare Containerd

Extract containerd binaries on the master node:

```bash
# Extract containerd binaries
tar -xzvpf containerd-1.7.20-linux-loong64.tar.gz

# Verify extracted files
ls -la bin/
```

## Step 5: Install Containerd on Target Nodes

### 5.1 Copy Containerd Files

```bash
# Copy containerd binaries to target nodes
ks scp ./bin --groups new-nodes --remote-path /root/bin --recursive

# Copy containerd configuration files
ks scp containerd_config.toml --groups new-nodes --remote-path /root/containerd_config.toml
ks scp containerd.service --groups new-nodes --remote-path /root/containerd.service

# Copy container images
ks scp pause.tar.gz --groups new-nodes --remote-path /root/pause.tar.gz
ks scp flannel-loong64.tar.gz --groups new-nodes --remote-path /root/flannel-loong64.tar.gz
ks scp flannel-cni-plugin-loong64.tar.gz --groups new-nodes --remote-path /root/flannel-cni-plugin-loong64.tar.gz
```

### 5.2 Install and Configure Containerd

```bash
# Create directories and install binaries
ks exec "mkdir -p /opt/kube/bin/ /opt/kube/bin/containerd-bin/ /etc/containerd/" --groups new-nodes

# Copy binaries to target locations
ks exec "cp /root/bin/* /opt/kube/bin/ && cp /root/bin/* /opt/kube/bin/containerd-bin/" --groups new-nodes

# Install configuration files
ks exec "cp /etc/containerd/config.toml /etc/containerd/config.toml" --groups new-nodes
ks exec "cp /etc/systemd/system/containerd.service /etc/systemd/system/containerd.service" --groups new-nodes

# Import pause image directly from compressed archive
ks exec "/opt/kube/bin/ctr -n k8s.io i import /root/pause.tar.gz" --groups new-nodes

# Import flannel image directly from compressed archive
ks exec "/opt/kube/bin/ctr -n k8s.io i import /root/flannel-loong64.tar.gz" --groups new-nodes
ks exec "/opt/kube/bin/ctr -n k8s.io i import /root/flannel-cni-plugin-loong64.tar.gz" --groups new-nodes

# Verify imported images (should show the correct tags already)
ks exec "/opt/kube/bin/ctr -n k8s.io i ls" --groups new-nodes

# Expected images after import:
# - registry.tecorigin.local:5000/easzlab/pause:3.9
# - registry.tecorigin.io:5443/infra/flannel/flannel:v0.22.1 
# - registry.tecorigin.io:5443/infra/flannel/flannel-cni-plugin:v1.4.0-flannel1 

# Enable and start containerd service
ks exec "systemctl daemon-reload && systemctl enable containerd && systemctl restart containerd" --groups new-nodes

# Verify containerd status
ks exec "systemctl status containerd --no-pager" --groups new-nodes
```

## Step 6: Extract and Prepare Kubernetes Binaries

```bash
# Extract Kubernetes node binaries
mkdir -p tmp-k8s
cd tmp-k8s
tar -xzvpf ../kubernetes-node-linux-loong64.tar.gz

# Verify extracted binaries
ls -la kubernetes/node/bin/
```

## Step 7: Generate Certificates and Service Files for Each Node

For each new node, generate kubelet certificates, kubeconfig files, and service configuration files. The `ks gencert` command automatically detects the cluster CIDR and kubelet data directory from the local master node configuration:

```bash
# Generate certificates and service files for worker-1 (auto-detects cluster CIDR and kubelet data dir)
ks gencert --hostname worker-1 --ip 192.168.1.100 --apiserver https://192.168.1.10:6443 --output-dir ./certs/worker-1

# Generate certificates and service files for worker-2 (repeat for each node)
ks gencert --hostname worker-2 --ip 192.168.1.101 --apiserver https://192.168.1.10:6443 --output-dir ./certs/worker-2

# Optional: Override auto-detected values if needed
# ks gencert --hostname worker-3 --ip 192.168.1.102 --apiserver https://192.168.1.10:6443 --output-dir ./certs/worker-3 --cluster-cidr 10.244.0.0/16 --kubelet-data-dir /var/lib/kubelet

# Verify generated files
ls -la ./certs/worker-1/
# Should contain: kubelet.pem, kubelet-key.pem, kubelet.kubeconfig, kube-proxy.kubeconfig, kubelet.service, kube-proxy-config.yaml
```

**Auto-Detection Features:**
- **Cluster CIDR**: Automatically read from `/var/lib/kube-proxy/kube-proxy-config.yaml` on the master node
- **Kubelet Data Directory**: Automatically read from `/etc/systemd/system/kubelet.service` on the master node
- **Fallback**: Uses default values if local configuration files are not found

## Step 8: Deploy Kubernetes Components

### 8.1 Copy Kubernetes Binaries

```bash
# Copy Kubernetes binaries to all nodes
ks scp tmp-k8s/kubernetes/node/bin/ --groups new-nodes --remote-path /root/k8s-bin --recursive

# Install binaries to system location
ks exec "cp /root/k8s-bin/* /opt/kube/bin/" --groups new-nodes

# Make binaries executable
ks exec "chmod +x /opt/kube/bin/*" --groups new-nodes
```

### 8.2 Copy Base Kubernetes Configuration

```bash
# Copy base Kubernetes configuration from master
ks scp /etc/kubernetes/ --groups new-nodes --remote-path /etc/kubernetes --recursive

# Copy kubelet configuration file (kube-proxy-config.yaml is generated per-node)
ks scp kubelet_config.yaml --groups new-nodes --remote-path /root/kubelet_config.yaml
ks scp kube-proxy.service --groups new-nodes --remote-path /root/kube-proxy.service
```

### 8.3 Deploy Node-Specific Certificates and Service Files

Deploy certificates and service configuration files for each node individually:

```bash
# Deploy certificates and service files for worker-1
ks scp ./certs/worker-1/kubelet.pem --hosts 192.168.1.100 --remote-path /etc/kubernetes/ssl/kubelet.pem
ks scp ./certs/worker-1/kubelet-key.pem --hosts 192.168.1.100 --remote-path /etc/kubernetes/ssl/kubelet-key.pem
ks scp ./certs/worker-1/kubelet.kubeconfig --hosts 192.168.1.100 --remote-path /etc/kubernetes/kubelet.kubeconfig
ks scp ./certs/worker-1/kube-proxy.kubeconfig --hosts 192.168.1.100 --remote-path /etc/kubernetes/kube-proxy.kubeconfig
ks scp ./certs/worker-1/kubelet.service --hosts 192.168.1.100 --remote-path /etc/systemd/system/kubelet.service
ks scp ./certs/worker-1/kube-proxy-config.yaml --hosts 192.168.1.100 --remote-path /var/lib/kube-proxy/kube-proxy-config.yaml

# Deploy certificates and service files for worker-2
ks scp ./certs/worker-2/kubelet.pem --hosts 192.168.1.101 --remote-path /etc/kubernetes/ssl/kubelet.pem
ks scp ./certs/worker-2/kubelet-key.pem --hosts 192.168.1.101 --remote-path /etc/kubernetes/ssl/kubelet-key.pem
ks scp ./certs/worker-2/kubelet.kubeconfig --hosts 192.168.1.101 --remote-path /etc/kubernetes/kubelet.kubeconfig
ks scp ./certs/worker-2/kube-proxy.kubeconfig --hosts 192.168.1.101 --remote-path /etc/kubernetes/kube-proxy.kubeconfig
ks scp ./certs/worker-2/kubelet.service --hosts 192.168.1.101 --remote-path /etc/systemd/system/kubelet.service
ks scp ./certs/worker-2/kube-proxy-config.yaml --hosts 192.168.1.101 --remote-path /var/lib/kube-proxy/kube-proxy-config.yaml

# Repeat for additional nodes...
```

## Step 9: Configure and Start Kubelet

```bash
# Create kubelet directories and install configuration
ks exec "mkdir -p /var/lib/kubelet/" --groups new-nodes
ks exec "cp /root/kubelet_config.yaml /var/lib/kubelet/config.yaml" --groups new-nodes
# Note: kubelet.service is now deployed per-node in step 8.3 with correct hostname/IP

# Set proper permissions for certificates
ks exec "chmod 600 /etc/kubernetes/ssl/kubelet-key.pem /etc/kubernetes/kubelet.kubeconfig" --groups new-nodes
ks exec "chmod 644 /etc/kubernetes/ssl/kubelet.pem" --groups new-nodes

# Disable swap (required for kubelet)
ks exec "swapoff -a && sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab" --groups new-nodes

# (Optional) Change kubelet's DNS setting to use kube-dns instead of node-local-dns
ks dns-update --groups new-nodes --kubelet-config /custom/path/kubelet/config.yaml

# Enable and start kubelet
ks exec "systemctl daemon-reload && systemctl enable kubelet && systemctl restart kubelet" --groups new-nodes

# Verify kubelet status
ks exec "systemctl status kubelet --no-pager" --groups new-nodes
```

## Step 10: Configure and Start Kube-proxy

```bash
# Create kube-proxy directories and install configuration
ks exec "mkdir -p /var/lib/kube-proxy/" --groups new-nodes
# Note: kube-proxy-config.yaml is now deployed per-node in step 8.3 with correct hostname/cluster CIDR
ks exec "cp /root/kube-proxy.service /etc/systemd/system/kube-proxy.service" --groups new-nodes

# Set proper permissions for kube-proxy kubeconfig
ks exec "chmod 600 /etc/kubernetes/kube-proxy.kubeconfig" --groups new-nodes

# Enable and start kube-proxy
ks exec "systemctl daemon-reload && systemctl enable kube-proxy && systemctl restart kube-proxy" --groups new-nodes

# Verify kube-proxy status
ks exec "systemctl status kube-proxy --no-pager" --groups new-nodes
```

## Step 11: Verify Node Addition

### 11.1 Check Node Status

```bash
# Check if nodes appear in the cluster
kubectl get nodes

# Check node details
kubectl describe node worker-1
kubectl describe node worker-2
```

### 11.2 Label Nodes

```bash
# Label nodes with appropriate roles
kubectl label node worker-1 kubernetes.io/role=node
kubectl label node worker-2 kubernetes.io/role=node

# Verify labels
kubectl get nodes --show-labels
```

### 11.3 Verify Services on Nodes

```bash
# Check all services are running properly
ks exec "systemctl status containerd kubelet kube-proxy --no-pager" --groups new-nodes

# Check kubelet logs if needed
ks exec "journalctl -u kubelet --no-pager -l" --groups new-nodes

# Check kube-proxy logs if needed
ks exec "journalctl -u kube-proxy --no-pager -l" --groups new-nodes
```

## Step 12: Post-Installation Verification

### 12.1 Verify Network Connectivity

```bash
# Test network connectivity between nodes
ks exec "ping -c 3 192.168.1.10" --groups new-nodes  # Ping master node

# Check if CNI is working properly
kubectl get pods -n kube-system -o wide | grep flannel
```

## Troubleshooting

### Common Issues and Solutions

1. **Kubelet fails to start**:
   ```bash
   # Check kubelet logs
   ks exec "journalctl -u kubelet -f" --groups new-nodes
   
   # Verify certificate permissions
   ks exec "ls -la /etc/kubernetes/ssl/" --groups new-nodes
   ```

2. **Node not joining cluster**:
   ```bash
   # Verify API server connectivity
   ks exec "curl -k https://192.168.1.10:6443/version" --groups new-nodes
   
   # Check kubeconfig files
   ks exec "cat /etc/kubernetes/kubelet.kubeconfig" --groups new-nodes
   ```

3. **Containerd issues**:
   ```bash
   # Check containerd status and logs
   ks exec "systemctl status containerd && journalctl -u containerd --no-pager -l" --groups new-nodes
   ```

4. **Certificate issues**:
   ```bash
   # Regenerate certificates if needed
   ks gencert --hostname worker-1 --ip 192.168.1.100 --apiserver https://192.168.1.10:6443 --output-dir ./certs/worker-1-new
   
   # Redeploy certificates
   ks scp ./certs/worker-1-new/kubelet.pem --hosts 192.168.1.100 --remote-path /etc/kubernetes/ssl/kubelet.pem
   ```

5. **Package installation issues**:
   ```bash
   # Check what package manager is available
   ks exec "command -v yum && echo 'YUM available' || echo 'YUM not available'" --groups new-nodes
   ks exec "command -v apt && echo 'APT available' || echo 'APT not available'" --groups new-nodes
   ks exec "command -v dnf && echo 'DNF available' || echo 'DNF not available'" --groups new-nodes
   
   # Manual package installation if automatic detection fails
   ks exec "yum install -y conntrack socat ipset" --groups new-nodes  # For RHEL/CentOS
   ks exec "apt update && apt install -y conntrack socat ipset" --groups new-nodes  # For Ubuntu/Debian
   ```

6. **Sysctl configuration issues**:
   ```bash
   # Check if sysctl file was copied correctly
   ks exec "ls -la /etc/sysctl.d/95-k8s-sysctl.conf" --groups new-nodes
   
   # Manually apply sysctl settings if needed
   ks exec "echo 'net.bridge.bridge-nf-call-iptables = 1' >> /etc/sysctl.conf && echo 'net.bridge.bridge-nf-call-ip6tables = 1' >> /etc/sysctl.conf && echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf" --groups new-nodes
   ks exec "sysctl -p" --groups new-nodes
   ```

## Automation Script

For multiple nodes, you can create a script to automate the certificate generation and deployment:

```bash
#!/bin/bash
# add-nodes.sh

NODES=(
    "worker-1:192.168.1.100"
    "worker-2:192.168.1.101"
    "worker-3:192.168.1.102"
)

API_SERVER="https://192.168.1.10:6443"
# Note: cluster CIDR and kubelet data directory are auto-detected from local master node config

for node_info in "${NODES[@]}"; do
    hostname=$(echo $node_info | cut -d: -f1)
    ip=$(echo $node_info | cut -d: -f2)
    
    echo "Generating certificates and service files for $hostname ($ip)..."
    ks gencert --hostname $hostname --ip $ip --apiserver $API_SERVER --output-dir ./certs/$hostname
    
    echo "Deploying certificates and service files for $hostname..."
    ks scp ./certs/$hostname/kubelet.pem --hosts $ip --remote-path /etc/kubernetes/ssl/kubelet.pem
    ks scp ./certs/$hostname/kubelet-key.pem --hosts $ip --remote-path /etc/kubernetes/ssl/kubelet-key.pem
    ks scp ./certs/$hostname/kubelet.kubeconfig --hosts $ip --remote-path /etc/kubernetes/kubelet.kubeconfig
    ks scp ./certs/$hostname/kube-proxy.kubeconfig --hosts $ip --remote-path /etc/kubernetes/kube-proxy.kubeconfig
    ks scp ./certs/$hostname/kubelet.service --hosts $ip --remote-path /etc/systemd/system/kubelet.service
    ks scp ./certs/$hostname/kube-proxy-config.yaml --hosts $ip --remote-path /var/lib/kube-proxy/kube-proxy-config.yaml
    
    echo "Labeling node $hostname..."
    kubectl label node $hostname kubernetes.io/role=node
done

echo "All nodes added successfully!"
```

## Security Notes

- Ensure proper file permissions for certificates and kubeconfig files
- Use strong passwords or SSH keys for authentication
- Consider using a secrets management system for production environments
- Regularly rotate certificates and update kubeconfig files
- Monitor node access and audit logs

## Summary

This guide provides a comprehensive approach to adding Kubernetes nodes using the `ks` tool, which significantly simplifies the process by:

- Automating file distribution across multiple nodes
- Generating proper certificates and kubeconfig files with auto-detection of cluster configuration
- Providing concurrent execution for faster deployment
- Offering detailed logging and troubleshooting capabilities
- Auto-detecting cluster CIDR and kubelet data directory from master node configuration

The `ks` tool's ad-hoc host support, smart credential lookup, and intelligent configuration detection make it particularly well-suited for Kubernetes cluster management tasks.