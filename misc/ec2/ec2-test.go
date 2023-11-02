package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"text/template"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/scionproto/scion/scion-pki/testcrypto"
)

const (
	usage = "<usage>"

	ec2ImageId                       = "ami-0d84a3c966e80e500"
	ec2InstanceCount                 = 6
	ec2InstanceKeyName               = "ddos-testnet"
	ec2InstanceName                  = "scion-time-test"
	ec2InstancePrivateIpAddressCount = 3
	ec2InstanceStateTerminated       = 48
	ec2InstanceType                  = types.InstanceTypeT4gXlarge
	ec2InstanceUser                  = "ec2-user"
	ec2Region                        = "eu-central-1"
	ec2SecurityGroupId               = "sg-0faa998b9f96f3ab2"
	ec2SubnetId                      = "subnet-0ff6cc969e67bd0ab"
)

const (
	testnetDstDir      = "/home/ec2-user/testnet"
	testnetGenDir      = "testnet/gen"
	testnetSrcDir      = "testnet"
	testnetTLSCertFile = "testnet/gen/tls.crt"
	testnetTLSKeyFile  = "testnet/gen/tls.key"
	testnetTopology    = "testnet/topology.topo"
	testnetTRCDir      = "testnet/gen/trcs"
)

var (
	installGoCommands = []string{
		"curl -LO https://go.dev/dl/go1.17.13.linux-arm64.tar.gz",
		"echo \"914daad3f011cc2014dea799bb7490442677e4ad6de0b2ac3ded6cee7e3f493d go1.17.13.linux-arm64.tar.gz\" | sha256sum -c",
		"sudo tar -C /usr/local -xzf go1.17.13.linux-arm64.tar.gz",
		"sudo mv /usr/local/go /usr/local/go1.17.13",
		"rm go1.17.13.linux-arm64.tar.gz",
		"curl -LO https://golang.org/dl/go1.21.2.linux-arm64.tar.gz",
		"echo \"23e208ca44a3cb46cd4308e48a27c714ddde9c8c34f2e4211dbca95b6d456554 go1.21.2.linux-arm64.tar.gz\" | sha256sum -c",
		"sudo tar -C /usr/local -xzf go1.21.2.linux-arm64.tar.gz",
		"sudo mv /usr/local/go /usr/local/go1.21.2",
		"rm go1.21.2.linux-arm64.tar.gz",
	}
	installSCIONCommands = []string{
		"sudo yum update",
		"sudo yum install -y git",
		"git clone https://github.com/scionproto/scion.git",
		"cd /home/ec2-user/scion && git checkout v0.9.1",
		"cd /home/ec2-user/scion && /usr/local/go1.21.2/bin/go build -o ./bin/ ./control/cmd/control",
		"cd /home/ec2-user/scion && /usr/local/go1.21.2/bin/go build -o ./bin/ ./daemon/cmd/daemon",
		"cd /home/ec2-user/scion && /usr/local/go1.21.2/bin/go build -o ./bin/ ./dispatcher/cmd/dispatcher",
		"cd /home/ec2-user/scion && /usr/local/go1.21.2/bin/go build -o ./bin/ ./router/cmd/router",
		"cd /home/ec2-user/scion && /usr/local/go1.21.2/bin/go build -o ./bin/ ./scion/cmd/scion",
	}
	installSNCCommands = []string{
		"sudo yum update",
		"sudo yum install -y git",
		"git clone https://github.com/marcfrei/scion.git scion-snc",
		"cd /home/ec2-user/scion-snc && git checkout marcfrei/br_scheduling_snc",
		"cd /home/ec2-user/scion-snc && /usr/local/go1.17.13/bin/go build -o ./bin/ ./go/posix-router",
		"ln -sf /home/ec2-user/scion-snc/bin/posix-router /home/ec2-user/scion/bin/router",
	}
	installTSCommands = []string{
		"sudo yum update",
		"sudo yum install -y git gcc make",
		"git clone https://github.com/marcfrei/scion-time.git",
		"cd /home/ec2-user/scion-time && git checkout marcfrei/offset-log",
		"cd /home/ec2-user/scion-time && /usr/local/go1.21.2/bin/go build timeservice.go timeservicex.go",
		"make -C /home/ec2-user/scion-time/testnet/ntimed",
	}
	installChronyCommands = []string{
		"sudo yum update",
		"sudo yum install -y git gcc make",
		"curl -LO https://chrony-project.org/releases/chrony-4.4.tar.gz",
		"tar -xzvf chrony-4.4.tar.gz ",
		"rm chrony-4.4.tar.gz",
		"mv chrony-4.4 chrony-4.4-src",
		"mkdir chrony-4.4",
		"cd /home/ec2-user/chrony-4.4-src && ./configure --prefix=/home/ec2-user/chrony-4.4",
		"cd /home/ec2-user/chrony-4.4-src && make install",
	}
	startServicesCommands = map[string][]string{
		"ASff00_0_110_INFRA": {
			"sudo cp /home/ec2-user/testnet/systemd/scion-border-router@.service /lib/systemd/system/scion-border-router@ASff00_0_110.service",
			"sudo cp /home/ec2-user/testnet/systemd/scion-control-service@.service /lib/systemd/system/scion-control-service@ASff00_0_110.service",
			"sudo cp /home/ec2-user/testnet/systemd/scion-daemon@.service /lib/systemd/system/scion-daemon@ASff00_0_110.service",
			"sudo cp /home/ec2-user/testnet/systemd/scion-dispatcher@.service /lib/systemd/system/scion-dispatcher@ASff00_0_110.service",
			"sudo systemctl daemon-reload",
			"sudo systemctl enable scion-border-router@ASff00_0_110.service",
			"sudo systemctl enable scion-control-service@ASff00_0_110.service",
			"sudo systemctl enable scion-daemon@ASff00_0_110.service",
			"sudo systemctl enable scion-dispatcher@ASff00_0_110.service",
			"sudo systemctl start scion-border-router@ASff00_0_110.service",
			"sudo systemctl start scion-control-service@ASff00_0_110.service",
			"sudo systemctl start scion-daemon@ASff00_0_110.service",
			"sudo systemctl start scion-dispatcher@ASff00_0_110.service",
		},
		"ASff00_0_120_INFRA": {
			"sudo cp /home/ec2-user/testnet/systemd/scion-border-router@.service /lib/systemd/system/scion-border-router@ASff00_0_120.service",
			"sudo cp /home/ec2-user/testnet/systemd/scion-control-service@.service /lib/systemd/system/scion-control-service@ASff00_0_120.service",
			"sudo cp /home/ec2-user/testnet/systemd/scion-daemon@.service /lib/systemd/system/scion-daemon@ASff00_0_120.service",
			"sudo cp /home/ec2-user/testnet/systemd/scion-dispatcher@.service /lib/systemd/system/scion-dispatcher@ASff00_0_120.service",
			"sudo systemctl daemon-reload",
			"sudo systemctl enable scion-border-router@ASff00_0_120.service",
			"sudo systemctl enable scion-control-service@ASff00_0_120.service",
			"sudo systemctl enable scion-daemon@ASff00_0_120.service",
			"sudo systemctl enable scion-dispatcher@ASff00_0_120.service",
			"sudo systemctl start scion-border-router@ASff00_0_120.service",
			"sudo systemctl start scion-control-service@ASff00_0_120.service",
			"sudo systemctl start scion-daemon@ASff00_0_120.service",
			"sudo systemctl start scion-dispatcher@ASff00_0_120.service",
		},
		"ASff00_0_130_INFRA": {
			"sudo cp /home/ec2-user/testnet/systemd/scion-border-router@.service /lib/systemd/system/scion-border-router@ASff00_0_130.service",
			"sudo cp /home/ec2-user/testnet/systemd/scion-control-service@.service /lib/systemd/system/scion-control-service@ASff00_0_130.service",
			"sudo cp /home/ec2-user/testnet/systemd/scion-daemon@.service /lib/systemd/system/scion-daemon@ASff00_0_130.service",
			"sudo cp /home/ec2-user/testnet/systemd/scion-dispatcher@.service /lib/systemd/system/scion-dispatcher@ASff00_0_130.service",
			"sudo systemctl daemon-reload",
			"sudo systemctl enable scion-border-router@ASff00_0_130.service",
			"sudo systemctl enable scion-control-service@ASff00_0_130.service",
			"sudo systemctl enable scion-daemon@ASff00_0_130.service",
			"sudo systemctl enable scion-dispatcher@ASff00_0_130.service",
			"sudo systemctl start scion-border-router@ASff00_0_130.service",
			"sudo systemctl start scion-control-service@ASff00_0_130.service",
			"sudo systemctl start scion-daemon@ASff00_0_130.service",
			"sudo systemctl start scion-dispatcher@ASff00_0_130.service",
		},
		"ASff00_0_110_TS": {
			"ln -sf /home/ec2-user/testnet/ASff00_0_110_TS_DSCP_0.toml /home/ec2-user/testnet/ASff00_0_110_TS.toml",
			"sudo cp /home/ec2-user/testnet/systemd/scion-daemon@.service /lib/systemd/system/scion-daemon@ASff00_0_110.service",
			"sudo cp /home/ec2-user/testnet/systemd/scion-timeservice-server.service /lib/systemd/system/scion-timeservice-server@ASff00_0_110.service",
			"sudo systemctl daemon-reload",
			"sudo systemctl enable scion-daemon@ASff00_0_110.service",
			"sudo systemctl enable scion-timeservice-server@ASff00_0_110.service",
			"sudo systemctl start scion-daemon@ASff00_0_110.service",
			"sudo systemctl start scion-timeservice-server@ASff00_0_110.service",
		},
		"ASff00_0_120_TS": {
			"ln -sf /home/ec2-user/testnet/ASff00_0_120_TS_DSCP_0.toml /home/ec2-user/testnet/ASff00_0_120_TS.toml",
			"sudo cp /home/ec2-user/testnet/systemd/scion-daemon@.service /lib/systemd/system/scion-daemon@ASff00_0_120.service",
			"sudo cp /home/ec2-user/testnet/systemd/scion-timeservice-client.service /lib/systemd/system/scion-timeservice-client@ASff00_0_120.service",
			"sudo systemctl daemon-reload",
			"sudo systemctl enable scion-daemon@ASff00_0_120.service",
			"sudo systemctl enable scion-timeservice-client@ASff00_0_120.service",
			"sudo systemctl start scion-daemon@ASff00_0_120.service",
			"sudo systemctl start scion-timeservice-client@ASff00_0_120.service",
		},
		"CHRONY": {
			"sudo cp /home/ec2-user/testnet/systemd/chrony.service /lib/systemd/system/chrony.service",
			"sudo systemctl daemon-reload",
			"sudo systemctl enable chrony.service",
			"sudo systemctl start chrony.service",
		},
	}
	testnetServices = []string{
		"ASff00_0_110_INFRA",
		"ASff00_0_120_INFRA",
		"ASff00_0_130_INFRA",
		"ASff00_0_110_TS",
		"ASff00_0_120_TS",
		"CHRONY",
	}
	testnetTemplates = map[string]bool{
		"testnet/gen/ASff00_0_110/topology.json": true,
		"testnet/gen/ASff00_0_120/topology.json": true,
		"testnet/gen/ASff00_0_130/topology.json": true,
		"testnet/ASff00_0_110_TS_DSCP_0.toml":    true,
		"testnet/ASff00_0_110_TS_DSCP_63.toml":   true,
		"testnet/ASff00_0_120_TS_DSCP_0.toml":    true,
		"testnet/ASff00_0_120_TS_DSCP_63.toml":   true,
	}
	testnetCryptoPaths = []string{
		"testnet/gen/certs",
		"testnet/gen/ISD1",
		"testnet/gen/trcs",
		"testnet/gen/ASff00_0_110/certs",
		"testnet/gen/ASff00_0_110/crypto",
		"testnet/gen/ASff00_0_110/keys",
		"testnet/gen/ASff00_0_120/certs",
		"testnet/gen/ASff00_0_120/crypto",
		"testnet/gen/ASff00_0_120/keys",
		"testnet/gen/ASff00_0_130/certs",
		"testnet/gen/ASff00_0_130/crypto",
		"testnet/gen/ASff00_0_130/keys",
	}
	testnetCryptoMasterKeys = []string{
		"testnet/gen/ASff00_0_110/keys/master0.key",
		"testnet/gen/ASff00_0_110/keys/master1.key",
		"testnet/gen/ASff00_0_120/keys/master0.key",
		"testnet/gen/ASff00_0_120/keys/master1.key",
		"testnet/gen/ASff00_0_130/keys/master0.key",
		"testnet/gen/ASff00_0_130/keys/master1.key",
	}
	testnetCertDirs = []string{
		"testnet/gen/ASff00_0_110/certs",
		"testnet/gen/ASff00_0_120/certs",
		"testnet/gen/ASff00_0_130/certs",
	}
)

func newEC2Client() *ec2.Client {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(ec2Region))
	if err != nil {
		log.Fatalf("LoadDefaultConfig failed: %v", err)
	}
	return ec2.NewFromConfig(cfg)
}

func listInstances() {
	client := newEC2Client()
	res, err := client.DescribeInstances(
		context.TODO(),
		&ec2.DescribeInstancesInput{},
	)
	if err != nil {
		log.Fatalf("DescribeInstances failed: %v", err)
	}
	for _, r := range res.Reservations {
		for _, i := range r.Instances {
			sort.Slice(i.Tags, func(x, y int) bool {
				return *i.Tags[x].Key < *i.Tags[y].Key
			})
			for _, t := range i.Tags {
				if *t.Key == "Name" && *t.Value == ec2InstanceName {
					fmt.Print(*i.InstanceId)
					fmt.Print(", ", i.State.Name)
					if i.PublicIpAddress != nil {
						fmt.Printf(", %15s", *i.PublicIpAddress)
					}
					for _, tt := range i.Tags {
						if *tt.Key == "Name" {
							fmt.Print(", ", *tt.Key, "=", *tt.Value)
						}
					}
					for _, tt := range i.Tags {
						if *tt.Key != "Name" {
							fmt.Print(", ", *tt.Key, "=", *tt.Value)
						}
					}
					fmt.Println()
				}
			}
		}
	}
}

func runCommand(sshClient *ssh.Client, instanceId, instanceAddr, command string) {
	for n := 0; n < 8; n++ {
		err := os.MkdirAll("logs", 0755)
		if err != nil {
			log.Printf("Failed to run command on instance %s (%s): %v", instanceId, instanceAddr, err)
			return
		}
		fn := fmt.Sprintf("./logs/%s-%s.txt", instanceId, instanceAddr)
		f, err := os.OpenFile(fn, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Failed to run command on instance %s (%s): %v", instanceId, instanceAddr, err)
			return
		}
		defer f.Close()
		sess, err := sshClient.NewSession()
		if err != nil {
			log.Printf("Failed to run command on instance %s (%s): %v", instanceId, instanceAddr, err)
			return
		}
		defer sess.Close()
		f.WriteString(fmt.Sprintf("$ %s\n", command))
		var wg sync.WaitGroup
		sessStdout, err := sess.StdoutPipe()
		if err != nil {
			log.Printf("Failed to run command on instance %s (%s): %v", instanceId, instanceAddr, err)
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			io.Copy(f, sessStdout)
		}()
		sessStderr, err := sess.StderrPipe()
		if err != nil {
			log.Printf("Failed to run command on instance %s (%s): %v", instanceId, instanceAddr, err)
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			io.Copy(f, sessStderr)
		}()
		err = sess.Run(command)
		wg.Wait()
		if err != nil {
			log.Printf("Failed to run command (%s) on instance %s (%s): %v", command, instanceId, instanceAddr, err)
		} else {
			break
		}
	}
}

func runCommands(sshClient *ssh.Client, instanceId, instanceAddr string, commands []string) {
	for _, command := range commands {
		runCommand(sshClient, instanceId, instanceAddr, command)
	}
}

func uploadFile(client *sftp.Client, dst, src string, data map[string]string) {
	d, err := client.Create(dst)
	if err != nil {
		log.Fatal(err)
	}
	defer d.Close()
	if testnetTemplates[src] {
		s, err := template.ParseFiles(src)
		if err != nil {
			log.Fatal(err)
		}
		err = s.Execute(d, data)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		s, err := os.Open(src)
		if err != nil {
			log.Fatal(err)
		}
		defer s.Close()

		_, err = d.ReadFrom(s)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func uploadDir(client *sftp.Client, dst, src string, data map[string]string) {
	es, err := os.ReadDir(src)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range es {
		n := e.Name()
		if n[0] != '.' {
			s := filepath.Join(src, n)
			d := filepath.Join(dst, n)
			if e.IsDir() {
				err = client.Mkdir(d)
				if err != nil {
					log.Fatalf("Mkdir failed: %v", err)
				}
				uploadDir(client, d, s, data)
			} else if e.Type().IsRegular() {
				uploadFile(client, d, s, data)
			}
		}
	}
}

func uploadTestnet(sshc *ssh.Client, data map[string]string) {
	sftpc, err := sftp.NewClient(sshc)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer sftpc.Close()
	src := testnetSrcDir
	dst := testnetDstDir
	err = sftpc.Mkdir(dst)
	if err != nil {
		log.Fatalf("Mkdir failed: %v", err)
	}
	uploadDir(sftpc, dst, src, data)
}

func sshIdentity(path string) ssh.AuthMethod {
	key, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("ReadFile (%s) failed: %v", path, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("ParsePrivateKey (%s) failed: %v", path, err)
	}
	return ssh.PublicKeys(signer)
}

func startServices(sshClient *ssh.Client, instanceId, instanceAddr, role string) {
	runCommands(sshClient, instanceId, instanceAddr, startServicesCommands[role])
}

func installChrony(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installChronyCommands)
}

func installTS(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installTSCommands)
}

func installSNC(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installSNCCommands)
}

func installSCION(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installSCIONCommands)
}

func installGo(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installGoCommands)
}

func addSecondaryAddrs(sshClient *ssh.Client, instanceId, instanceAddr string, data map[string]string) {
	role := data[instanceId]
	if role != "" {
		for k := 1; k < ec2InstancePrivateIpAddressCount; k++ {
			addr := data[role+"_IP_"+strconv.Itoa(k)]
			if addr != "" {
				cmd := fmt.Sprintf("sudo ip address add %s/32 dev ens5 noprefixroute || true", addr)
				runCommand(sshClient, instanceId, instanceAddr, cmd)
			}
		}
	}
}

func setupInstance(wg *sync.WaitGroup, instanceId, instanceAddr,
	sshIdentityFile string, doInstallSNC bool, data map[string]string) {
	defer wg.Done()
	log.Printf("Connecting to instance %s...\n", instanceId)
	sshConfig := &ssh.ClientConfig{
		User: ec2InstanceUser,
		Auth: []ssh.AuthMethod{
			sshIdentity(sshIdentityFile),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	hostAddr := fmt.Sprintf("%s:22", instanceAddr)
	var sshClient *ssh.Client
	for i := 0; i < 60; i++ {
		sshClient, _ = ssh.Dial("tcp", hostAddr, sshConfig)
		if sshClient != nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if sshClient == nil {
		log.Printf("Failed to connect to instance %s", instanceId)
		return
	}
	defer sshClient.Close()
	addSecondaryAddrs(sshClient, instanceId, instanceAddr, data)
	log.Printf("Installing Go on instance %s...\n", instanceId)
	installGo(sshClient, instanceId, instanceAddr)
	log.Printf("Installing SCION on instance %s...\n", instanceId)
	installSCION(sshClient, instanceId, instanceAddr)
	if doInstallSNC {
		log.Printf("Installing SNC on instance %s...\n", instanceId)
		installSNC(sshClient, instanceId, instanceAddr)
	}
	log.Printf("Installing TS on instance %s...\n", instanceId)
	installTS(sshClient, instanceId, instanceAddr)
	log.Printf("Installing chrony on instance %s...\n", instanceId)
	installChrony(sshClient, instanceId, instanceAddr)
	log.Printf("Installing testnet on instance %s...\n", instanceId)
	uploadTestnet(sshClient, data)
	role := data[instanceId]
	if role != "" {
		log.Printf("Starting %s services on instance %s...\n", role, instanceId)
		startServices(sshClient, instanceId, instanceAddr, role)
	}
}

func genTLSCertificate() {
	// Based on go/src/crypto/tls/generate_cert.go
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(28 * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	certFile, err := os.Create(testnetTLSCertFile)
	if err != nil {
		log.Fatalf("Failed to create tls.crt for writing: %v", err)
	}
	defer certFile.Close()
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		log.Fatalf("Failed to write data to tls.crt: %v", err)
	}
	keyFile, err := os.OpenFile(testnetTLSKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to create tls.key for writing: %v", err)
	}
	defer keyFile.Close()
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		log.Fatalf("Failed to write data to tls.key: %v", err)
	}
}

type commandPather string

func (s commandPather) CommandPath() string {
	return string(s)
}

func delCryptoMaterial() {
	for _, p := range testnetCryptoPaths {
		_ = os.RemoveAll(p)
	}
	_ = os.Remove(testnetTLSCertFile)
	_ = os.Remove(testnetTLSKeyFile)
}

func genCryptoMaterial() {
	delCryptoMaterial()
	cmd := testcrypto.Cmd(commandPather(""))
	cmd.SetArgs([]string{"-t", testnetTopology, "-o", testnetGenDir, "--as-validity", "28d"})
	stdout, stderr := os.Stdout, os.Stderr
	null, err := os.Open(os.DevNull)
	if err != nil {
		panic(err)
	}
	func() {
		os.Stdout, os.Stderr = null, null
		defer func() {
			os.Stdout, os.Stderr = stdout, stderr
		}()
		err = cmd.Execute()
	}()
	if err != nil {
		log.Fatalf("testcrypto failed: %v", err)
	}
	genMasterKeyFile := func(name string) {
		x := make([]byte, 16)
		n, err := rand.Read(x)
		if err != nil {
			panic(err)
		}
		if n != len(x) {
			panic("rand.Read failed")
		}
		f, err := os.Create(name)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		b := make([]byte, base64.StdEncoding.EncodedLen(len(x)))
		base64.StdEncoding.Encode(b, x)
		n, err = f.Write(b)
		if err != nil {
			panic(err)
		}
		if n != len(b) {
			panic("Write failed")
		}
	}
	for _, k := range testnetCryptoMasterKeys {
		genMasterKeyFile(k)
	}
	copyDir := func(src, dst string) {
		es, err := os.ReadDir(src)
		if err != nil {
			log.Fatal(err)
		}
		for _, e := range es {
			n := e.Name()
			if n[0] != '.' {
				if e.IsDir() {
					panic("not yet implemented")
				} else if e.Type().IsRegular() {
					copyFile := func(src, dst string) {
						s, err := os.Open(src)
						if err != nil {
							log.Fatal(err)
						}
						defer s.Close()
						d, err := os.Create(dst)
						if err != nil {
							panic(err)
						}
						defer d.Close()
						_, err = d.ReadFrom(s)
						if err != nil {
							log.Fatal(err)
						}
					}
					copyFile(filepath.Join(src, n), filepath.Join(dst, n))
				}
			}
		}
	}
	for _, dst := range testnetCertDirs {
		copyDir(testnetTRCDir, dst)
	}
	genTLSCertificate()
}

func setup(sshIdentityFile string, doInstallSNC bool) {
	client := newEC2Client()
	var instanceCount int32 = ec2InstanceCount
	if instanceCount == 1 {
		log.Printf("Creating %d instance...", instanceCount)
	} else {
		log.Printf("Creating %d instances...", instanceCount)
	}
	res, err := client.RunInstances(
		context.TODO(),
		&ec2.RunInstancesInput{
			ImageId:          aws.String(ec2ImageId),
			InstanceType:     ec2InstanceType,
			KeyName:          aws.String(ec2InstanceKeyName),
			MinCount:         &instanceCount,
			MaxCount:         &instanceCount,
			SecurityGroupIds: []string{ec2SecurityGroupId},
			SubnetId:         aws.String(ec2SubnetId),
		},
	)
	if err != nil {
		log.Fatalf("RunInstances failed: %v", err)
	}

	instances := map[string]string{}

	for _, i := range res.Instances {
		instances[*i.InstanceId] = ""
		if len(i.NetworkInterfaces) != 1 {
			log.Fatalf("Unexpected network interface configuration: %s", *i.InstanceId)
		}
		var addressCount int32 = ec2InstancePrivateIpAddressCount - 1
		_, err = client.AssignPrivateIpAddresses(
			context.TODO(),
			&ec2.AssignPrivateIpAddressesInput{
				NetworkInterfaceId:             i.NetworkInterfaces[0].NetworkInterfaceId,
				SecondaryPrivateIpAddressCount: &addressCount,
			},
		)
		if err != nil {
			log.Fatalf("AssignPrivateIpAddresses failed: %v", err)
		}
		_, err = client.CreateTags(
			context.TODO(),
			&ec2.CreateTagsInput{
				Resources: []string{*i.InstanceId},
				Tags: []types.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(ec2InstanceName),
					},
				},
			},
		)
		if err != nil {
			log.Fatalf("CreateTags failed: %v", err)
		}
	}

	if len(instances) != ec2InstanceCount {
		log.Fatalf("setup failed")
	}

	data := map[string]string{}

	n := 0
	s := 0
	for i := 0; n < ec2InstanceCount && i < 60; i++ {
		res, err := client.DescribeInstances(
			context.TODO(),
			&ec2.DescribeInstancesInput{},
		)
		if err != nil {
			log.Fatalf("DescribeInstances failed: %v", err)
		}
		for _, r := range res.Reservations {
			for _, i := range r.Instances {
				if i.PublicIpAddress != nil {
					if _, ok := instances[*i.InstanceId]; ok {
						if instances[*i.InstanceId] != *i.PublicIpAddress {
							instances[*i.InstanceId] = *i.PublicIpAddress
							if s != len(testnetServices) {
								data[*i.InstanceId] = testnetServices[s]
								_, err = client.CreateTags(
									context.TODO(),
									&ec2.CreateTagsInput{
										Resources: []string{*i.InstanceId},
										Tags: []types.Tag{
											{
												Key:   aws.String("Role"),
												Value: aws.String(testnetServices[s]),
											},
										},
									},
								)
								if err != nil {
									log.Fatalf("CreateTags failed: %v", err)
								}
								for _, ni := range i.NetworkInterfaces {
									for k, a := range ni.PrivateIpAddresses {
										if k == 0 && !*a.Primary {
											panic("TODO")
										}
										t := testnetServices[s] + "_IP_" + strconv.Itoa(k)
										data[t] = *a.PrivateIpAddress
									}
								}
								s++
							}
							n++
						}
					}
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

	if n != ec2InstanceCount {
		log.Fatalf("setup failed")
	}

	genCryptoMaterial()
	defer delCryptoMaterial()
	var wg sync.WaitGroup
	for instanceId, instanceAddr := range instances {
		wg.Add(1)
		go setupInstance(&wg, instanceId, instanceAddr, sshIdentityFile, doInstallSNC, data)
	}
	wg.Wait()
}

func teardown() {
	client := newEC2Client()
	var instanceIds []string
	res, err := client.DescribeInstances(
		context.TODO(),
		&ec2.DescribeInstancesInput{},
	)
	if err != nil {
		log.Fatalf("DescribeInstances failed: %v", err)
	}
	for _, r := range res.Reservations {
		for _, i := range r.Instances {
			if *i.State.Code != ec2InstanceStateTerminated {
				for _, t := range i.Tags {
					if *t.Key == "Name" && *t.Value == ec2InstanceName {
						instanceIds = append(instanceIds, *i.InstanceId)
					}
				}
			}
		}
	}
	if len(instanceIds) != 0 {
		_, err = client.TerminateInstances(
			context.TODO(),
			&ec2.TerminateInstancesInput{
				InstanceIds: instanceIds,
			},
		)
		if err != nil {
			log.Fatalf("TerminateInstances failed: %v", err)
		}
	}
}

func exitWithUsage() {
	fmt.Println(usage)
	os.Exit(1)
}

func main() {
	listFlags := flag.NewFlagSet("list", flag.ExitOnError)
	setupFlags := flag.NewFlagSet("setup", flag.ExitOnError)
	teardownFlags := flag.NewFlagSet("teardown", flag.ExitOnError)

	var sshIdentityFile string
	var doInstallSNC bool

	setupFlags.StringVar(&sshIdentityFile, "i", "", "ssh identity file")
	setupFlags.BoolVar(&doInstallSNC, "snc", true, "SNC installation")

	if len(os.Args) < 2 {
		exitWithUsage()
	}

	switch os.Args[1] {
	case "list":
		err := listFlags.Parse(os.Args[2:])
		if err != nil || listFlags.NArg() != 0 {
			exitWithUsage()
		}
		listInstances()
	case "setup":
		err := setupFlags.Parse(os.Args[2:])
		if err != nil || setupFlags.NArg() != 0 {
			exitWithUsage()
		}
		setup(sshIdentityFile, doInstallSNC)
	case "teardown":
		err := teardownFlags.Parse(os.Args[2:])
		if err != nil || teardownFlags.NArg() != 0 {
			exitWithUsage()
		}
		teardown()
	default:
		exitWithUsage()
	}
}
