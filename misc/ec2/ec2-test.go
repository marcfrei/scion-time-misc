package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
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
	installTestnetCommands = []string{
		"mkdir /home/ec2-user/testnet",
		"mkdir /home/ec2-user/testnet/gen",
		"mkdir /home/ec2-user/testnet/systemd",
		"mkdir /home/ec2-user/testnet/gen/ASff00_0_110",
		"mkdir /home/ec2-user/testnet/gen/ASff00_0_120",
		"mkdir /home/ec2-user/testnet/gen/ASff00_0_130",
	}	
	testnetFiles = map[string]string{
		"./testnet/gen/ASff00_0_110/br1.toml":                "/home/ec2-user/testnet/gen/ASff00_0_110/br1.toml",
		"./testnet/gen/ASff00_0_110/cs1.toml":                "/home/ec2-user/testnet/gen/ASff00_0_110/cs1.toml",
		"./testnet/gen/ASff00_0_110/dispatcher.toml":         "/home/ec2-user/testnet/gen/ASff00_0_110/dispatcher.toml",
		"./testnet/gen/ASff00_0_110/sd1.toml":                "/home/ec2-user/testnet/gen/ASff00_0_110/sd1.toml",
		"./testnet/gen/ASff00_0_110/topology.json":           "/home/ec2-user/testnet/gen/ASff00_0_110/topology.json",
		"./testnet/gen/ASff00_0_120/br1.toml":                "/home/ec2-user/testnet/gen/ASff00_0_120/br1.toml",
		"./testnet/gen/ASff00_0_120/cs1.toml":                "/home/ec2-user/testnet/gen/ASff00_0_120/cs1.toml",
		"./testnet/gen/ASff00_0_120/dispatcher.toml":         "/home/ec2-user/testnet/gen/ASff00_0_120/dispatcher.toml",
		"./testnet/gen/ASff00_0_120/sd1.toml":                "/home/ec2-user/testnet/gen/ASff00_0_120/sd1.toml",
		"./testnet/gen/ASff00_0_120/topology.json":           "/home/ec2-user/testnet/gen/ASff00_0_120/topology.json",
		"./testnet/gen/ASff00_0_130/br1.toml":                "/home/ec2-user/testnet/gen/ASff00_0_130/br1.toml",
		"./testnet/gen/ASff00_0_130/cs1.toml":                "/home/ec2-user/testnet/gen/ASff00_0_130/cs1.toml",
		"./testnet/gen/ASff00_0_130/dispatcher.toml":         "/home/ec2-user/testnet/gen/ASff00_0_130/dispatcher.toml",
		"./testnet/gen/ASff00_0_130/sd1.toml":                "/home/ec2-user/testnet/gen/ASff00_0_130/sd1.toml",
		"./testnet/gen/ASff00_0_130/topology.json":           "/home/ec2-user/testnet/gen/ASff00_0_130/topology.json",
		"./testnet/systemd/scion-border-router@.service":     "/home/ec2-user/testnet/systemd/scion-border-router@.service",
		"./testnet/systemd/scion-control-service@.service":   "/home/ec2-user/testnet/systemd/scion-control-service@.service",
		"./testnet/systemd/scion-daemon@.service":            "/home/ec2-user/testnet/systemd/scion-daemon@.service",
		"./testnet/systemd/scion-dispatcher@.service":        "/home/ec2-user/testnet/systemd/scion-dispatcher@.service",
		"./testnet/systemd/scion-timeservice-client.service": "/home/ec2-user/testnet/systemd/scion-timeservice-client.service",
		"./testnet/systemd/scion-timeservice-server.service": "/home/ec2-user/testnet/systemd/scion-timeservice-server.service",
		"./testnet/client.toml":                              "/home/ec2-user/testnet/client.toml",
		"./testnet/server.toml":                              "/home/ec2-user/testnet/server.toml",
		"./testnet/topology.topo":                            "/home/ec2-user/testnet/topology.topo",
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

func uploadFile(client *ssh.Client, instanceId, instanceAddr, srcPath, dstPath string) {
	src, err := os.Open(srcPath)
	if err != nil {
		log.Printf("Failed to upload file to instance %s (%s): %v", instanceId, instanceAddr, err)
		return
	}
	defer src.Close()

	uploadData(client, instanceId, instanceAddr, src, dstPath)
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

func uploadTestnet(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installTestnetCommands)
	for src, dst := range testnetFiles {
		uploadFile(sshClient, instanceId, instanceAddr, src, dst)
	}
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
	installGo(sshClient, instanceId, instanceAddr)
	installSCION(sshClient, instanceId, instanceAddr)
	installSNC(sshClient, instanceId, instanceAddr)
	installTS(sshClient, instanceId, instanceAddr)
	uploadTestnet(sshClient, instanceId, instanceAddr)
}

func setup(sshIdentityFile string) {
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
