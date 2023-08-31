package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
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

	ec2ImageId                       = "ami-0b2bca38b9ad1d86b"
	ec2InstanceCount                 = 1
	ec2InstanceKeyName               = "ddos-testnet"
	ec2InstanceName                  = "scion-time-test"
	ec2InstancePrivateIpAddressCount = 3
	ec2InstanceStateTerminated       = 48
	ec2InstanceType                  = types.InstanceTypeT4gSmall
	ec2InstanceUser                  = "ec2-user"
	ec2Region                        = "eu-central-1"
	ec2SecurityGroupId               = "sg-0faa998b9f96f3ab2"
	ec2SubnetId                      = "subnet-0ff6cc969e67bd0ab"
)

var (
	installGoCommands = []string{
		"curl -LO https://go.dev/dl/go1.17.13.linux-arm64.tar.gz",
		"echo \"914daad3f011cc2014dea799bb7490442677e4ad6de0b2ac3ded6cee7e3f493d go1.17.13.linux-arm64.tar.gz\" | sha256sum -c",
		"sudo tar -C /usr/local -xzf go1.17.13.linux-arm64.tar.gz",
		"sudo mv /usr/local/go /usr/local/go1.17.13",
		"rm go1.17.13.linux-arm64.tar.gz",
		"curl -LO https://golang.org/dl/go1.19.12.linux-arm64.tar.gz",
		"echo \"18da7cf1ae5341e6ee120948221aff96df9145ce70f429276514ca7c67c929b1 go1.19.12.linux-arm64.tar.gz\" | sha256sum -c",
		"sudo tar -C /usr/local -xzf go1.19.12.linux-arm64.tar.gz",
		"sudo mv /usr/local/go /usr/local/go1.19.12",
		"rm go1.19.12.linux-arm64.tar.gz",
	}
	installSCIONCommands = []string{
		"sudo yum update",
		"sudo yum install -y git",
		"git clone https://github.com/scionproto/scion.git",
		"cd /home/ec2-user/scion && /usr/local/go1.19.12/bin/go build -o ./bin/ ./control/cmd/control",
		"cd /home/ec2-user/scion && /usr/local/go1.19.12/bin/go build -o ./bin/ ./daemon/cmd/daemon",
		"cd /home/ec2-user/scion && /usr/local/go1.19.12/bin/go build -o ./bin/ ./dispatcher/cmd/dispatcher",
		"cd /home/ec2-user/scion && /usr/local/go1.19.12/bin/go build -o ./bin/ ./router/cmd/router",
		"cd /home/ec2-user/scion && /usr/local/go1.19.12/bin/go build -o ./bin/ ./scion/cmd/scion",
	}
	installSNCCommands = []string{
		"sudo yum update",
		"sudo yum install -y git",
		"git clone https://github.com/netsec-ethz/scion.git scion-snc",
		"cd /home/ec2-user/scion-snc && git checkout br_scheduling_snc",
		"cd /home/ec2-user/scion-snc && /usr/local/go1.17.13/bin/go build -o ./bin/ ./go/posix-router",
		"ln -sf /home/ec2-user/scion-snc/bin/posix-router /home/ec2-user/scion/bin/router",
	}
	installTSCommands = []string{
		"sudo yum update",
		"sudo yum install -y git",
		"git clone https://github.com/marcfrei/scion-time.git",
		"cd /home/ec2-user/scion-time && /usr/local/go1.19.12/bin/go build timeservice.go timeservicex.go",
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
	testnetTrcMap = map[string]string{
		"testnet/gen/ISD1/trcs": "testnet/gen/ISD1",
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
			for _, t := range i.Tags {
				if *t.Key == "Name" && *t.Value == ec2InstanceName {
					fmt.Print(*i.InstanceId)
					fmt.Print(", ", i.State.Name)
					if i.PublicIpAddress != nil {
						fmt.Print(", ", *i.PublicIpAddress)
					}
					for _, tt := range i.Tags {
						fmt.Print(", ", *tt.Key, "=", *tt.Value)
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

func uploadData(client *ssh.Client, instanceId, instanceAddr string, srcRd io.Reader, dstPath string) {
	sftp, err := sftp.NewClient(client)
	if err != nil {
		log.Printf("Failed to upload file to instance %s (%s): %v", instanceId, instanceAddr, err)
		return
	}
	defer sftp.Close()

	dst, err := sftp.Create(dstPath)
	if err != nil {
		log.Printf("Failed to upload file to instance %s (%s): %v @1 %s", instanceId, instanceAddr, err, dstPath)
		return
	}
	defer dst.Close()

	_, err = dst.ReadFrom(srcRd)
	if err != nil {
		log.Printf("Failed to upload file to instance %s (%s): %v", instanceId, instanceAddr, err)
		return
	}
}

func uploadFile(client *sftp.Client, src, dst string) {
	s, err := os.Open(src)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	d, err := client.Create(dst)
	if err != nil {
		log.Fatal(err)
	}
	defer d.Close()

	_, err = d.ReadFrom(s)
	if err != nil {
		log.Fatal(err)
	}
}

func uploadDir(client *sftp.Client, src, dst string) {
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
				uploadDir(client, s, d)
			} else if e.Type().IsRegular() {
				uploadFile(client, s, d)
			}
		}
	}
}

func uploadTestnet(sshc *ssh.Client) {
	sftpc, err := sftp.NewClient(sshc)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer sftpc.Close()

	dst := "/home/ec2-user/testnet"

	err = sftpc.Mkdir(dst)
	if err != nil {
		log.Fatalf("Mkdir failed: %v", err)
	}

	uploadDir(sftpc, "testnet", dst)
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

type commandPather string

func (s commandPather) CommandPath() string {
	return string(s)
}

func genCryptoMaterial() {
	for _, p := range testnetCryptoPaths {
		_ = os.RemoveAll(p)
	}
	cmd := testcrypto.Cmd(commandPather(""))
	cmd.SetArgs([]string{"-t", "testnet/topology.topo", "-o", "testnet/gen", "--as-validity", "28d"})
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
		defer func() {
			err = f.Close()
			if err != nil {
				panic(err)
			}
		}()
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
						defer func() {
							err = s.Close()
							if err != nil {
								panic(err)
							}
						}()
						d, err := os.Create(dst)
						if err != nil {
							panic(err)
						}
						defer func() {
							err = d.Close()
							if err != nil {
								panic(err)
							}
						}()
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
	for src, dst := range testnetTrcMap {
		copyDir(src, dst)
	}
	os.Exit(0)
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

func setupInstance(wg *sync.WaitGroup, instanceId, instanceAddr, sshIdentityFile string) {
	defer wg.Done()

	sshConfig := &ssh.ClientConfig{
		User: ec2InstanceUser,
		Auth: []ssh.AuthMethod{
			sshIdentity(sshIdentityFile),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if instanceAddr == "" {
		log.Printf("Failed to connect to instance %s", instanceId)
		return
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

	runCommand(sshClient, instanceId, instanceAddr, "uname -a")
	// installGo(sshClient, instanceId, instanceAddr)
	// installSCION(sshClient, instanceId, instanceAddr)
	// installSNC(sshClient, instanceId, instanceAddr)
	// installTS(sshClient, instanceId, instanceAddr)
	uploadTestnet(sshClient)
}

func setup(sshIdentityFile string) {
	genCryptoMaterial()

	client := newEC2Client()

	var instanceCount int32 = ec2InstanceCount
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

	n := 0
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

	var wg sync.WaitGroup
	for instanceId, instanceAddr := range instances {
		wg.Add(1)
		go setupInstance(&wg, instanceId, instanceAddr, sshIdentityFile)
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

	setupFlags.StringVar(&sshIdentityFile, "i", "", "ssh identity file")

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
		setup(sshIdentityFile)
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
