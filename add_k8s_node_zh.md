# 使用 ks 工具添加 Kubernetes 节点操作手册

## 概述

本手册提供了使用 `ks` 工具向现有 Kubernetes 集群添加新节点的详细操作步骤。本方法特别适用于：
- 非标准架构的节点（如 LoongArch64、RISC-V 等）
- 自定义 Linux 发行版
- 需要手动控制安装过程的环境
- kubeasz 不支持的特殊场景

## 前置条件

- 现有 Kubernetes 集群（至少一个 master 节点）
- 在 master 节点上安装并配置好 `ks` 工具
- 准备好以下文件：
  - `containerd-1.7.20-linux-loong64.tar.gz` - containerd 运行时
  - `kubernetes-node-linux-loong64.tar.gz` - Kubernetes 节点组件
  - 离线容器镜像：`pause.tar.gz`、`flannel-loong64.tar.gz`、`flannel-cni-plugin-loong64.tar.gz`
  - `node-rbac.yaml` - 节点 RBAC 配置

- **配置文件可从本地 master 节点复制**：
  - `/etc/containerd/config.toml` - containerd 配置文件
  - `/etc/systemd/system/containerd.service` - containerd 服务文件
  - `/etc/systemd/system/kube-proxy.service` - kube-proxy 服务文件
  - `/var/lib/kubelet/config.yaml` - kubelet 基础配置文件
  - `/etc/sysctl.d/95-k8s-sysctl.conf` - 系统内核参数配置

## 步骤一：应用节点 RBAC 配置

在 **master 节点** 上执行，为新节点配置必要的权限：

```bash
# 应用节点 RBAC 配置
kubectl apply -f node-rbac.yaml

# 验证 RBAC 资源创建成功
kubectl get clusterrole system:node-lease-access
kubectl get clusterrolebinding system:node-lease-access-binding
```

## 步骤二：准备主机配置文件

创建 `hosts.yaml` 配置文件：

```yaml
groups:
  - name: new-nodes
    hosts:
      - ip: 192.168.1.100
        hostname: worker-1
      - ip: 192.168.1.101
        hostname: worker-2
    username: root
    password: your_password    # 替换为实际密码
    port: 22
```

## 步骤三：系统环境准备

### 3.1 安装必需软件包

```bash
# 智能检测包管理器并安装必需软件包
ks exec 'if command -v yum >/dev/null 2>&1; then
    echo "使用 YUM 包管理器"
    yum install -y conntrack socat ipset
elif command -v dnf >/dev/null 2>&1; then
    echo "使用 DNF 包管理器"
    dnf install -y conntrack socat ipset
elif command -v apt >/dev/null 2>&1; then
    echo "使用 APT 包管理器"
    apt update && apt install -y conntrack socat ipset
elif command -v zypper >/dev/null 2>&1; then
    echo "使用 Zypper 包管理器"
    zypper install -y conntrack socat ipset
else
    echo "未找到支持的包管理器"
    exit 1
fi' --groups new-nodes

# 验证软件包安装
ks exec "which conntrack && which socat && which ipset && echo '所有软件包安装成功'" --groups new-nodes
```

### 3.2 配置系统参数

```bash
# 复制系统内核参数配置文件
ks scp /etc/sysctl.d/95-k8s-sysctl.conf --groups new-nodes --remote-path /etc/sysctl.d/95-k8s-sysctl.conf

# 应用系统参数
ks exec "sysctl --system" --groups new-nodes
```

## 步骤四：安装 containerd 容器运行时

### 4.1 解压并准备 containerd

```bash
# 在 master 节点解压 containerd
tar -xzvpf containerd-1.7.20-linux-loong64.tar.gz

# 验证解压结果
ls -la bin/
```

### 4.2 部署 containerd 到目标节点

```bash
# 复制 containerd 二进制文件
ks scp ./bin --groups new-nodes --remote-path /root/bin --recursive

# 从本地 master 节点复制配置文件
ks scp /etc/containerd/config.toml --groups new-nodes --remote-path /root/containerd_config.toml
ks scp /etc/systemd/system/containerd.service --groups new-nodes --remote-path /root/containerd.service

# 复制容器镜像
ks scp pause.tar.gz --groups new-nodes --remote-path /root/pause.tar.gz
ks scp flannel-loong64.tar.gz --groups new-nodes --remote-path /root/flannel-loong64.tar.gz
ks scp flannel-cni-plugin-loong64.tar.gz --groups new-nodes --remote-path /root/flannel-cni-plugin-loong64.tar.gz
```

### 4.3 安装和配置 containerd

```bash
# 创建目录
ks exec "mkdir -p /opt/kube/bin/ /opt/kube/bin/containerd-bin/ /etc/containerd/" --groups new-nodes

# 安装二进制文件
ks exec "cp /root/bin/* /opt/kube/bin/ && cp /root/bin/* /opt/kube/bin/containerd-bin/" --groups new-nodes

# 安装配置文件
ks exec "cp /root/containerd_config.toml /etc/containerd/config.toml" --groups new-nodes
ks exec "cp /root/containerd.service /etc/systemd/system/containerd.service" --groups new-nodes

# 导入容器镜像
ks exec "/opt/kube/bin/ctr -n k8s.io i import /root/pause.tar.gz" --groups new-nodes
ks exec "/opt/kube/bin/ctr -n k8s.io i import /root/flannel-loong64.tar.gz" --groups new-nodes
ks exec "/opt/kube/bin/ctr -n k8s.io i import /root/flannel-cni-plugin-loong64.tar.gz" --groups new-nodes

# 验证镜像导入
ks exec "/opt/kube/bin/ctr -n k8s.io i ls" --groups new-nodes

# 启动 containerd 服务
ks exec "systemctl daemon-reload && systemctl enable containerd && systemctl restart containerd" --groups new-nodes

# 验证 containerd 状态
ks exec "systemctl status containerd --no-pager" --groups new-nodes
```

## 步骤五：安装 Kubernetes 组件

### 5.1 解压 Kubernetes 二进制文件

```bash
# 解压 Kubernetes 节点组件
mkdir -p tmp-k8s
cd tmp-k8s
tar -xzvpf ../kubernetes-node-linux-loong64.tar.gz

# 验证解压结果
ls -la kubernetes/node/bin/
```

### 5.2 生成节点证书和配置文件

使用 `ks gencert` 命令为每个节点生成证书和配置文件：

```bash
# 为 worker-1 生成证书和配置（自动检测集群配置）
ks gencert --hostname worker-1 --ip 192.168.1.100 --apiserver https://192.168.1.10:6443 --output-dir ./certs/worker-1

# 为 worker-2 生成证书和配置
ks gencert --hostname worker-2 --ip 192.168.1.101 --apiserver https://192.168.1.10:6443 --output-dir ./certs/worker-2

# 验证生成的文件
ls -la ./certs/worker-1/
# 应包含：kubelet.pem, kubelet-key.pem, kubelet.kubeconfig, kube-proxy.kubeconfig, kubelet.service, kube-proxy-config.yaml
```

**自动检测功能**：
- **集群 CIDR**：自动从 `/var/lib/kube-proxy/kube-proxy-config.yaml` 读取
- **kubelet 数据目录**：自动从 `/etc/systemd/system/kubelet.service` 读取
- **备用默认值**：如果本地配置文件不存在或无法解析，使用默认值

## 步骤六：部署 Kubernetes 组件

### 6.1 复制 Kubernetes 二进制文件

```bash
# 复制 Kubernetes 二进制文件到所有节点
ks scp tmp-k8s/kubernetes/node/bin/ --groups new-nodes --remote-path /root/k8s-bin --recursive

# 安装到系统位置
ks exec "cp /root/k8s-bin/* /opt/kube/bin/" --groups new-nodes

# 设置执行权限
ks exec "chmod +x /opt/kube/bin/*" --groups new-nodes
```

### 6.2 复制基础配置文件

```bash
# 复制 Kubernetes 基础配置
ks scp /etc/kubernetes/ --groups new-nodes --remote-path /etc/kubernetes --recursive

# 从本地 master 节点复制配置文件
ks scp /var/lib/kubelet/config.yaml --groups new-nodes --remote-path /root/kubelet_config.yaml
ks scp /etc/systemd/system/kube-proxy.service --groups new-nodes --remote-path /root/kube-proxy.service
```

### 6.3 部署节点特定的证书和配置文件

为每个节点单独部署其专用的证书和配置：

```bash
# 部署 worker-1 的证书和配置
ks scp ./certs/worker-1/kubelet.pem --hosts 192.168.1.100 --remote-path /etc/kubernetes/ssl/kubelet.pem
ks scp ./certs/worker-1/kubelet-key.pem --hosts 192.168.1.100 --remote-path /etc/kubernetes/ssl/kubelet-key.pem
ks scp ./certs/worker-1/kubelet.kubeconfig --hosts 192.168.1.100 --remote-path /etc/kubernetes/kubelet.kubeconfig
ks scp ./certs/worker-1/kube-proxy.kubeconfig --hosts 192.168.1.100 --remote-path /etc/kubernetes/kube-proxy.kubeconfig
ks scp ./certs/worker-1/kubelet.service --hosts 192.168.1.100 --remote-path /etc/systemd/system/kubelet.service
ks scp ./certs/worker-1/kube-proxy-config.yaml --hosts 192.168.1.100 --remote-path /var/lib/kube-proxy/kube-proxy-config.yaml

# 部署 worker-2 的证书和配置
ks scp ./certs/worker-2/kubelet.pem --hosts 192.168.1.101 --remote-path /etc/kubernetes/ssl/kubelet.pem
ks scp ./certs/worker-2/kubelet-key.pem --hosts 192.168.1.101 --remote-path /etc/kubernetes/ssl/kubelet-key.pem
ks scp ./certs/worker-2/kubelet.kubeconfig --hosts 192.168.1.101 --remote-path /etc/kubernetes/kubelet.kubeconfig
ks scp ./certs/worker-2/kube-proxy.kubeconfig --hosts 192.168.1.101 --remote-path /etc/kubernetes/kube-proxy.kubeconfig
ks scp ./certs/worker-2/kubelet.service --hosts 192.168.1.101 --remote-path /etc/systemd/system/kubelet.service
ks scp ./certs/worker-2/kube-proxy-config.yaml --hosts 192.168.1.101 --remote-path /var/lib/kube-proxy/kube-proxy-config.yaml

# 继续为其他节点部署...
```

## 步骤七：配置和启动 kubelet

```bash
# 创建 kubelet 目录并安装配置
ks exec "mkdir -p /var/lib/kubelet/" --groups new-nodes
ks exec "cp /root/kubelet_config.yaml /var/lib/kubelet/config.yaml" --groups new-nodes

# 设置证书文件权限
ks exec "chmod 600 /etc/kubernetes/ssl/kubelet-key.pem /etc/kubernetes/kubelet.kubeconfig" --groups new-nodes
ks exec "chmod 644 /etc/kubernetes/ssl/kubelet.pem" --groups new-nodes

# 禁用 swap（kubelet 要求）
ks exec "swapoff -a && sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab" --groups new-nodes

# 更新 kubelet DNS 配置（可选，使用集群 DNS 而不是节点本地 DNS）
ks dns-update --groups new-nodes

# 启动 kubelet 服务
ks exec "systemctl daemon-reload && systemctl enable kubelet && systemctl restart kubelet" --groups new-nodes

# 验证 kubelet 状态
ks exec "systemctl status kubelet --no-pager" --groups new-nodes
```

## 步骤八：配置和启动 kube-proxy

```bash
# 创建 kube-proxy 目录
ks exec "mkdir -p /var/lib/kube-proxy/" --groups new-nodes

# 安装 kube-proxy 服务文件
ks exec "cp /root/kube-proxy.service /etc/systemd/system/kube-proxy.service" --groups new-nodes

# 设置 kube-proxy kubeconfig 权限
ks exec "chmod 600 /etc/kubernetes/kube-proxy.kubeconfig" --groups new-nodes

# 启动 kube-proxy 服务
ks exec "systemctl daemon-reload && systemctl enable kube-proxy && systemctl restart kube-proxy" --groups new-nodes

# 验证 kube-proxy 状态
ks exec "systemctl status kube-proxy --no-pager" --groups new-nodes
```

## 步骤九：验证节点添加

### 9.1 检查节点状态

```bash
# 检查节点是否出现在集群中
kubectl get nodes

# 查看节点详细信息
kubectl describe node worker-1
kubectl describe node worker-2
```

### 9.2 标记节点角色

```bash
# 为节点添加角色标签
kubectl label node worker-1 kubernetes.io/role=node
kubectl label node worker-2 kubernetes.io/role=node

# 验证标签
kubectl get nodes --show-labels
```

### 9.3 验证服务状态

```bash
# 检查所有服务运行状态
ks exec "systemctl status containerd kubelet kube-proxy --no-pager" --groups new-nodes

# 查看 kubelet 日志（如有需要）
ks exec "journalctl -u kubelet --no-pager -l" --groups new-nodes

# 查看 kube-proxy 日志（如有需要）
ks exec "journalctl -u kube-proxy --no-pager -l" --groups new-nodes
```

## 步骤十：验证网络连通性

```bash
# 测试节点间网络连通性
ks exec "ping -c 3 192.168.1.10" --groups new-nodes  # ping master 节点

# 检查 CNI 网络组件状态
kubectl get pods -n kube-system -o wide | grep flannel
```

## 自动化脚本

对于多个节点，可以使用以下自动化脚本：

```bash
#!/bin/bash
# add-nodes.sh - 批量添加节点脚本

NODES=(
    "worker-1:192.168.1.100"
    "worker-2:192.168.1.101"
    "worker-3:192.168.1.102"
)

API_SERVER="https://192.168.1.10:6443"

for node_info in "${NODES[@]}"; do
    hostname=$(echo $node_info | cut -d: -f1)
    ip=$(echo $node_info | cut -d: -f2)
    
    echo "正在为 $hostname ($ip) 生成证书和配置文件..."
    ks gencert --hostname $hostname --ip $ip --apiserver $API_SERVER --output-dir ./certs/$hostname
    
    echo "正在为 $hostname 部署证书和配置文件..."
    ks scp ./certs/$hostname/kubelet.pem --hosts $ip --remote-path /etc/kubernetes/ssl/kubelet.pem
    ks scp ./certs/$hostname/kubelet-key.pem --hosts $ip --remote-path /etc/kubernetes/ssl/kubelet-key.pem
    ks scp ./certs/$hostname/kubelet.kubeconfig --hosts $ip --remote-path /etc/kubernetes/kubelet.kubeconfig
    ks scp ./certs/$hostname/kube-proxy.kubeconfig --hosts $ip --remote-path /etc/kubernetes/kube-proxy.kubeconfig
    ks scp ./certs/$hostname/kubelet.service --hosts $ip --remote-path /etc/systemd/system/kubelet.service
    ks scp ./certs/$hostname/kube-proxy-config.yaml --hosts $ip --remote-path /var/lib/kube-proxy/kube-proxy-config.yaml
    
    echo "正在为节点 $hostname 添加标签..."
    kubectl label node $hostname kubernetes.io/role=node
done

echo "所有节点添加完成！"
```

## 故障排除

### 常见问题和解决方案

1. **kubelet 启动失败**：
   ```bash
   # 查看 kubelet 日志
   ks exec "journalctl -u kubelet -f" --groups new-nodes
   
   # 验证证书权限
   ks exec "ls -la /etc/kubernetes/ssl/" --groups new-nodes
   ```

2. **节点未加入集群**：
   ```bash
   # 验证 API server 连通性
   ks exec "curl -k https://192.168.1.10:6443/version" --groups new-nodes
   
   # 检查 kubeconfig 文件
   ks exec "cat /etc/kubernetes/kubelet.kubeconfig" --groups new-nodes
   ```

3. **containerd 问题**：
   ```bash
   # 检查 containerd 状态和日志
   ks exec "systemctl status containerd && journalctl -u containerd --no-pager -l" --groups new-nodes
   ```

4. **证书问题**：
   ```bash
   # 重新生成证书
   ks gencert --hostname worker-1 --ip 192.168.1.100 --apiserver https://192.168.1.10:6443 --output-dir ./certs/worker-1-new
   
   # 重新部署证书
   ks scp ./certs/worker-1-new/kubelet.pem --hosts 192.168.1.100 --remote-path /etc/kubernetes/ssl/kubelet.pem
   ```

5. **DNS 配置问题**：
   ```bash
   # 检查当前 DNS 配置
   ks exec "cat /var/lib/kubelet/config.yaml | grep -A 2 -i dns" --groups new-nodes
   
   # 更新 DNS 配置
   ks dns-update --groups new-nodes
   ```

## 安全注意事项

- 确保证书和 kubeconfig 文件的权限正确设置
- 使用强密码或 SSH 密钥进行身份验证
- 考虑在生产环境中使用密钥管理系统
- 定期轮换证书和更新 kubeconfig 文件
- 监控节点访问和审计日志

## 总结

本操作手册提供了使用 `ks` 工具添加 Kubernetes 节点的完整流程，通过以下方式简化了部署过程：

- **自动化文件分发**：跨多个节点并发执行文件复制
- **智能证书生成**：自动检测集群配置并生成适当的证书和 kubeconfig 文件
- **并发执行**：提高部署速度
- **详细日志记录**：便于故障排除
- **DNS 配置管理**：自动更新 kubelet DNS 设置

`ks` 工具的即席主机支持、智能凭据查找和配置自动检测功能，使其特别适合 Kubernetes 集群管理任务。
