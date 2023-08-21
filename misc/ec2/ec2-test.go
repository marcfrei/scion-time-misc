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

	"golang.org/x/crypto/ssh"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	usage = "<usage>"

	ec2InstanceStatePending    = 0
	ec2InstanceStateRunning    = 16
	ec2InstanceStateTerminated = 48

	ec2ImageId         = "ami-0b2bca38b9ad1d86b"
	ec2InstanceCount   = 5
	ec2InstanceKeyName = "ddos-testnet"
	ec2InstanceName    = "scion-time-test"
	ec2InstanceType    = types.InstanceTypeT4gMicro
	ec2InstanceUser    = "ec2-user"
	ec2Region          = "eu-central-1"
	ec2SecurityGroupId = "sg-0faa998b9f96f3ab2"
	ec2SubnetId        = "subnet-0ff6cc969e67bd0ab"
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

	input := &ec2.DescribeInstancesInput{}
	output, err := client.DescribeInstances(context.TODO(), input)
	if err != nil {
		log.Fatalf("DescribeInstances failed: %v", err)
	}
	for _, r := range output.Reservations {
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

func runCommand(client *ssh.Client, instanceId, instanceAddr, command string) {
	for n := 0; n < 8; n++ {
		err := os.MkdirAll("logs", 0755)
		if err != nil {
			log.Printf("Failed to run command on instance %s (%s): %v", instanceId, instanceAddr, err)
			return
		}
		fileName := fmt.Sprintf("./logs/%s-%s.txt", instanceId, instanceAddr)
		f, err := os.OpenFile(fileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Failed to run command on instance %s (%s): %v", instanceId, instanceAddr, err)
			return
		}
		defer f.Close()
		sess, err := client.NewSession()
		if err != nil {
			log.Printf("Failed to run command on instance %s (%s): %v", instanceId, instanceAddr, err)
			return
		}
		defer sess.Close()
		f.WriteString(fmt.Sprintf("$ %s\n", command))
		var wg sync.WaitGroup
		sessStdOut, err := sess.StdoutPipe()
		if err != nil {
			log.Printf("Failed to run command on instance %s (%s): %v", instanceId, instanceAddr, err)
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			io.Copy(f, sessStdOut)
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
}

func setup(sshIdentityFile string) {
	client := newEC2Client()

	var minCount, maxCount int32 = ec2InstanceCount, ec2InstanceCount

	input := &ec2.RunInstancesInput{
		ImageId:          aws.String(ec2ImageId),
		InstanceType:     ec2InstanceType,
		KeyName:          aws.String(ec2InstanceKeyName),
		MinCount:         &minCount,
		MaxCount:         &maxCount,
		SecurityGroupIds: []string{ec2SecurityGroupId},
		SubnetId:         aws.String(ec2SubnetId),
	}
	output, err := client.RunInstances(context.TODO(), input)
	if err != nil {
		log.Fatalf("RunInstances failed: %v", err)
	}

	instances := map[string]string{}

	for _, i := range output.Instances {
		instances[*i.InstanceId] = ""
		tagInput := &ec2.CreateTagsInput{
			Resources: []string{*i.InstanceId},
			Tags: []types.Tag{
				{
					Key:   aws.String("Name"),
					Value: aws.String(ec2InstanceName),
				},
			},
		}
		_, err = client.CreateTags(context.TODO(), tagInput)
		if err != nil {
			log.Fatalf("CreateTags failed: %v", err)
		}
	}

	if len(instances) != ec2InstanceCount {
		log.Fatalf("setup failed")
	}

	n := 0
	for i := 0; n < ec2InstanceCount && i < 60; i++ {
		input := &ec2.DescribeInstancesInput{}
		output, err := client.DescribeInstances(context.TODO(), input)
		if err != nil {
			log.Fatalf("DescribeInstances failed: %v", err)
		}
		for _, r := range output.Reservations {
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

	diInput := &ec2.DescribeInstancesInput{}
	diOutput, err := client.DescribeInstances(context.TODO(), diInput)
	if err != nil {
		log.Fatalf("DescribeInstances failed: %v", err)
	}
	for _, r := range diOutput.Reservations {
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
		tiInput := &ec2.TerminateInstancesInput{
			InstanceIds: instanceIds,
		}
		_, err = client.TerminateInstances(context.TODO(), tiInput)
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
