package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

// NewGenCertCmd creates a new gencert command
func NewGenCertCmd() *cobra.Command {
	var (
		hostname            string
		ipAddress           string
		apiServer           string
		caFile              string
		caKeyFile           string
		certFile            string
		keyFile             string
		kubeconfigFile      string
		kubeProxyConfigFile string
		outputDir           string
		country             string
		state               string
		locality            string
		organization        string
		orgUnit             string
	)

	genCertCmd := &cobra.Command{
		Use:   "gencert",
		Short: "Generate kubelet certificates and kubeconfig files",
		Long: `Generate kubelet certificates and kubeconfig files for Kubernetes nodes.

This command creates kubelet certificates signed by the specified CA certificate
and generates corresponding kubeconfig files with base64-encoded certificates.
It generates both kubelet.kubeconfig and kube-proxy.kubeconfig files using the
same certificates. The generated certificates include proper subject alternative 
names (SANs) for both hostname and IP address.

Examples:
  # Generate kubelet cert and kubeconfig files for a node
  ks gencert --hostname worker-1 --ip 192.168.1.100
  
  # Generate with custom API server address
  ks gencert --hostname master-1 --ip 10.0.1.10 --apiserver https://10.0.1.10:6443
  
  # Generate with custom CA files
  ks gencert --hostname master-1 --ip 10.0.1.10 --ca-file /path/to/ca.pem --ca-key-file /path/to/ca-key.pem
  
  # Generate with custom output paths
  ks gencert --hostname node-1 --ip 172.16.1.50 --cert-file /tmp/kubelet.pem --key-file /tmp/kubelet-key.pem --kubeconfig-file /tmp/kubelet.kubeconfig --kube-proxy-config-file /tmp/kube-proxy.kubeconfig
  
  # Generate with custom certificate details
  ks gencert --hostname node-1 --ip 192.168.1.10 --country US --state California --locality "San Francisco"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateKubeletCert(hostname, ipAddress, apiServer, caFile, caKeyFile, certFile, keyFile, kubeconfigFile, kubeProxyConfigFile, outputDir,
				country, state, locality, organization, orgUnit)
		},
	}

	genCertCmd.Flags().StringVar(&hostname, "hostname", "", "Hostname of the target node (required)")
	genCertCmd.Flags().StringVar(&ipAddress, "ip", "", "IP address of the target node (required)")
	genCertCmd.Flags().StringVar(&apiServer, "apiserver", "https://127.0.0.1:6443", "Kubernetes API server address")
	genCertCmd.Flags().StringVar(&caFile, "ca-file", "/etc/kubernetes/ssl/ca.pem", "Path to CA certificate file")
	genCertCmd.Flags().StringVar(&caKeyFile, "ca-key-file", "/etc/kubernetes/ssl/ca-key.pem", "Path to CA private key file")
	genCertCmd.Flags().StringVar(&certFile, "cert-file", "/etc/kubernetes/ssl/kubelet.pem", "Output path for kubelet certificate")
	genCertCmd.Flags().StringVar(&keyFile, "key-file", "/etc/kubernetes/ssl/kubelet-key.pem", "Output path for kubelet private key")
	genCertCmd.Flags().StringVar(&kubeconfigFile, "kubeconfig-file", "/etc/kubernetes/kubelet.kubeconfig", "Output path for kubelet kubeconfig")
	genCertCmd.Flags().StringVar(&kubeProxyConfigFile, "kube-proxy-config-file", "/etc/kubernetes/kube-proxy.kubeconfig", "Output path for kube-proxy kubeconfig")
	genCertCmd.Flags().StringVar(&outputDir, "output-dir", "", "Output directory for generated files (overrides cert-file, key-file, and kubeconfig files)")
	genCertCmd.Flags().StringVar(&country, "country", "CN", "Country name for certificate subject")
	genCertCmd.Flags().StringVar(&state, "state", "HangZhou", "State or province name for certificate subject")
	genCertCmd.Flags().StringVar(&locality, "locality", "XS", "Locality name for certificate subject")
	genCertCmd.Flags().StringVar(&organization, "organization", "system:nodes", "Organization name for certificate subject")
	genCertCmd.Flags().StringVar(&orgUnit, "org-unit", "System", "Organizational unit for certificate subject")

	genCertCmd.MarkFlagRequired("hostname")
	genCertCmd.MarkFlagRequired("ip")

	return genCertCmd
}

// generateKubeletCert generates kubelet certificate, key, and kubeconfig files
func generateKubeletCert(hostname, ipAddress, apiServer, caFile, caKeyFile, certFile, keyFile, kubeconfigFile, kubeProxyConfigFile, outputDir,
	country, state, locality, organization, orgUnit string) error {

	// Show warning if using default API server address
	if apiServer == "https://127.0.0.1:6443" {
		klog.Warningf("Using default API server address: %s", apiServer)
		klog.Warningf("Please double-check if this is the correct API server address for your cluster")
	}

	// Determine output paths
	var finalCertFile, finalKeyFile, finalKubeconfigFile, finalKubeProxyConfigFile string
	if outputDir != "" {
		// Ensure output directory exists
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}
		finalCertFile = filepath.Join(outputDir, "kubelet.pem")
		finalKeyFile = filepath.Join(outputDir, "kubelet-key.pem")
		finalKubeconfigFile = filepath.Join(outputDir, "kubelet.kubeconfig")
		finalKubeProxyConfigFile = filepath.Join(outputDir, "kube-proxy.kubeconfig")
	} else {
		finalCertFile = certFile
		finalKeyFile = keyFile
		finalKubeconfigFile = kubeconfigFile
		finalKubeProxyConfigFile = kubeProxyConfigFile

		// Ensure output directories exist
		certDir := filepath.Dir(finalCertFile)
		keyDir := filepath.Dir(finalKeyFile)
		kubeconfigDir := filepath.Dir(finalKubeconfigFile)
		kubeProxyConfigDir := filepath.Dir(finalKubeProxyConfigFile)

		for _, dir := range []string{certDir, keyDir, kubeconfigDir, kubeProxyConfigDir} {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %v", dir, err)
			}
		}
	}

	// Backup existing files if they are critical system files
	if err := backupExistingFiles(finalCertFile, finalKeyFile, finalKubeconfigFile, finalKubeProxyConfigFile); err != nil {
		return fmt.Errorf("failed to backup existing files: %v", err)
	}

	// Validate CA files exist
	if _, err := os.Stat(caFile); os.IsNotExist(err) {
		return fmt.Errorf("CA certificate file not found: %s", caFile)
	}
	if _, err := os.Stat(caKeyFile); os.IsNotExist(err) {
		return fmt.Errorf("CA private key file not found: %s", caKeyFile)
	}

	klog.Infof("Generating kubelet certificate for hostname: %s, IP: %s", hostname, ipAddress)

	// Create temporary directory for intermediate files
	tempDir, err := os.MkdirTemp("", "kubelet-cert-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	csrConfFile := filepath.Join(tempDir, "kubelet-csr.conf")
	csrFile := filepath.Join(tempDir, "kubelet.csr")
	tempKeyFile := filepath.Join(tempDir, "kubelet-key.pem")

	// Generate CSR configuration file
	if err := generateCSRConfig(csrConfFile, hostname, ipAddress, country, state, locality, organization, orgUnit); err != nil {
		return fmt.Errorf("failed to generate CSR config: %v", err)
	}

	// Generate private key
	klog.V(2).Infof("Generating private key...")
	if err := runCommand("openssl", "genrsa", "-out", tempKeyFile, "2048"); err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Generate certificate signing request
	klog.V(2).Infof("Generating certificate signing request...")
	subject := fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=system:node:%s",
		country, state, locality, organization, orgUnit, hostname)

	if err := runCommand("openssl", "req", "-new", "-key", tempKeyFile,
		"-out", csrFile, "-config", csrConfFile, "-subj", subject); err != nil {
		return fmt.Errorf("failed to generate CSR: %v", err)
	}

	// Sign certificate with CA
	klog.V(2).Infof("Signing certificate with CA...")
	tempCertFile := filepath.Join(tempDir, "kubelet.pem")
	if err := runCommand("openssl", "x509", "-req", "-in", csrFile,
		"-CA", caFile, "-CAkey", caKeyFile, "-CAcreateserial",
		"-out", tempCertFile, "-days", "18250", "-extensions", "v3_req",
		"-extfile", csrConfFile); err != nil {
		return fmt.Errorf("failed to sign certificate: %v", err)
	}

	// Copy generated files to final locations
	if err := copyFile(tempCertFile, finalCertFile); err != nil {
		return fmt.Errorf("failed to copy certificate: %v", err)
	}
	if err := copyFile(tempKeyFile, finalKeyFile); err != nil {
		return fmt.Errorf("failed to copy private key: %v", err)
	}

	// Set appropriate permissions
	if err := os.Chmod(finalCertFile, 0644); err != nil {
		klog.Warningf("Failed to set certificate permissions: %v", err)
	}
	if err := os.Chmod(finalKeyFile, 0600); err != nil {
		klog.Warningf("Failed to set private key permissions: %v", err)
	}

	// Generate kubelet kubeconfig file
	klog.V(2).Infof("Generating kubelet kubeconfig file...")
	if err := generateKubeconfig(finalKubeconfigFile, apiServer, caFile, finalCertFile, finalKeyFile, hostname); err != nil {
		return fmt.Errorf("failed to generate kubelet kubeconfig: %v", err)
	}

	// Generate kube-proxy kubeconfig file
	klog.V(2).Infof("Generating kube-proxy kubeconfig file...")
	if err := generateKubeProxyConfig(finalKubeProxyConfigFile, apiServer, caFile, finalCertFile, finalKeyFile); err != nil {
		return fmt.Errorf("failed to generate kube-proxy kubeconfig: %v", err)
	}

	// Set kubeconfig permissions
	if err := os.Chmod(finalKubeconfigFile, 0600); err != nil {
		klog.Warningf("Failed to set kubelet kubeconfig permissions: %v", err)
	}
	if err := os.Chmod(finalKubeProxyConfigFile, 0600); err != nil {
		klog.Warningf("Failed to set kube-proxy kubeconfig permissions: %v", err)
	}

	klog.Infof("Successfully generated kubelet certificate and kubeconfig files:")
	klog.Infof("  Certificate: %s", finalCertFile)
	klog.Infof("  Private Key: %s", finalKeyFile)
	klog.Infof("  Kubelet Kubeconfig: %s", finalKubeconfigFile)
	klog.Infof("  Kube-proxy Kubeconfig: %s", finalKubeProxyConfigFile)

	// Verify certificate
	klog.V(2).Infof("Verifying generated certificate...")
	if err := runCommand("openssl", "x509", "-in", finalCertFile, "-text", "-noout"); err != nil {
		klog.Warningf("Failed to verify certificate: %v", err)
	}

	return nil
}

// generateKubeconfig creates the kubeconfig file with base64-encoded certificates
func generateKubeconfig(kubeconfigFile, apiServer, caFile, certFile, keyFile, hostname string) error {
	// Read and encode CA certificate
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}
	caBase64 := base64.StdEncoding.EncodeToString(caData)

	// Read and encode client certificate
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read client certificate: %v", err)
	}
	certBase64 := base64.StdEncoding.EncodeToString(certData)

	// Read and encode client key
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read client key: %v", err)
	}
	keyBase64 := base64.StdEncoding.EncodeToString(keyData)

	// Generate kubeconfig content
	kubeconfigContent := fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: system:node:%s
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: system:node:%s
  user:
    client-certificate-data: %s
    client-key-data: %s
`, caBase64, apiServer, hostname, hostname, certBase64, keyBase64)

	// Write kubeconfig file
	return os.WriteFile(kubeconfigFile, []byte(kubeconfigContent), 0600)
}

// generateKubeProxyConfig creates the kube-proxy kubeconfig file with base64-encoded certificates
func generateKubeProxyConfig(kubeconfigFile, apiServer, caFile, certFile, keyFile string) error {
	// Read and encode CA certificate
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}
	caBase64 := base64.StdEncoding.EncodeToString(caData)

	// Read and encode client certificate
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read client certificate: %v", err)
	}
	certBase64 := base64.StdEncoding.EncodeToString(certData)

	// Read and encode client key
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read client key: %v", err)
	}
	keyBase64 := base64.StdEncoding.EncodeToString(keyData)

	// Generate kube-proxy kubeconfig content
	kubeconfigContent := fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kube-proxy
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: kube-proxy
  user:
    client-certificate-data: %s
    client-key-data: %s
`, caBase64, apiServer, certBase64, keyBase64)

	// Write kubeconfig file
	return os.WriteFile(kubeconfigFile, []byte(kubeconfigContent), 0600)
}

// generateCSRConfig creates the OpenSSL configuration file for CSR generation
func generateCSRConfig(configFile, hostname, ipAddress, country, state, locality, organization, orgUnit string) error {
	config := fmt.Sprintf(`[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]
countryName = %s
stateOrProvinceName = %s
localityName = %s
organizationName = %s
organizationalUnitName = %s
commonName = system:node:%s

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = %s
IP.1 = 127.0.0.1
IP.2 = %s
`, country, state, locality, organization, orgUnit, hostname, hostname, ipAddress)

	return os.WriteFile(configFile, []byte(config), 0644)
}

// runCommand executes a shell command and returns error if it fails
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	klog.V(3).Infof("Running command: %s %s", name, strings.Join(args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s\nOutput: %s", err, string(output))
	}

	if klog.V(4).Enabled() {
		klog.Infof("Command output: %s", string(output))
	}

	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// backupExistingFiles backs up critical system files if they exist
func backupExistingFiles(certFile, keyFile, kubeconfigFile, kubeProxyConfigFile string) error {
	// List of critical files that should be backed up
	criticalFiles := map[string]bool{
		"/etc/kubernetes/kubelet.kubeconfig":    true,
		"/etc/kubernetes/kube-proxy.kubeconfig": true,
		"/etc/kubernetes/ssl/kubelet.pem":       true,
		"/etc/kubernetes/ssl/kubelet-key.pem":   true,
	}

	filesToBackup := []string{certFile, keyFile, kubeconfigFile, kubeProxyConfigFile}

	for _, file := range filesToBackup {
		// Only backup if it's a critical system file and exists
		if criticalFiles[file] {
			if _, err := os.Stat(file); err == nil {
				backupFile := file + ".bak"
				klog.Infof("Backing up existing file: %s -> %s", file, backupFile)

				// Use os.Rename to move the file (atomic operation)
				if err := os.Rename(file, backupFile); err != nil {
					return fmt.Errorf("failed to backup %s: %v", file, err)
				}
				klog.Infof("Successfully backed up %s", file)
			}
		}
	}

	return nil
}
