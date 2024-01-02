package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"image/color"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
	"gonum.org/v1/plot/vg/draw"
	"gonum.org/v1/plot/vg/vgpdf"
)

const (
	usage = "<usage>"
)

const (
	ec2ImageId                       = "ami-0ba27d9989b7d8c5d"
	ec2InstanceCount                 = 6
	ec2InstanceName                  = "scion-time-ec2-test"
	ec2InstancePrivateIpAddressCount = 1
	ec2InstanceStateRunning          = 16
	ec2InstanceStateTerminated       = 48
	ec2InstanceType                  = types.InstanceTypeT4gXlarge
	ec2InstanceUser                  = "ec2-user"
)

const (
	testnetDstDir = "/home/ec2-user/testnet"
	testnetSrcDir = "testnet"
)

const (
	attackPreparation = 30 * time.Second
	attackDuration    = 150 * time.Second
)

var (
	installIPerf3Commands = []string{
		"sudo yum update",
		"sudo yum install -y iperf3",
	}
	installIProuteCommands = []string{
		"sudo yum update",
		"sudo yum install -y iproute-tc",
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
	installNtimedToolCommands = []string{
		"sudo yum update",
		"sudo yum install -y gcc",
		"curl -LO https://raw.githubusercontent.com/marcfrei/scion-time/marcfrei/offset-log/testnet/ntimed/ntimed-tool.c",
		"gcc -Wall -lm ntimed-tool.c -o ntimed-tool",
	}
	startServicesCommands = map[string][]string{
		"AS_A_INFRA": {
			"sudo sysctl -w net.ipv4.ip_forward=1",
			"sudo sysctl -w net.ipv6.conf.all.forwarding=1",
			"sudo ip route add $AS_B_TS_IP_0/32 via $AS_B_INFRA_IP_0 dev ens5",
			"sudo ip route add $AS_A_TS_IP_0/32 via $AS_A_TS_IP_0 dev ens5",
		},
		"AS_B_INFRA": {
			"sudo sysctl -w net.ipv4.ip_forward=1",
			"sudo sysctl -w net.ipv6.conf.all.forwarding=1",
			"sudo ip route add $AS_A_TS_IP_0/32 via $AS_A_INFRA_IP_0 dev ens5",
			"sudo ip route add $AS_B_TS_IP_0/32 via $AS_B_TS_IP_0 dev ens5",
			"sudo ip route add $LGS_IP_0/32 via $LGS_IP_0 dev ens5",
			"sudo ip route add $LGC_IP_0/32 via $LGC_IP_0 dev ens5",
			"sudo tc qdisc add dev ens5 root handle 1: htb default 7",
			"sudo tc class add dev ens5 parent 1:0 classid 1:1 htb rate 5000mbit",
			"sudo tc class add dev ens5 parent 1:1 classid 1:2 htb rate 100kbit prio 1",
			"sudo tc class add dev ens5 parent 1:1 classid 1:3 htb rate 100kbit prio 1",
			"sudo tc class add dev ens5 parent 1:1 classid 1:4 htb rate 1500mbit prio 2",
			"sudo tc class add dev ens5 parent 1:1 classid 1:5 htb rate 1500mbit prio 2",
			"sudo tc class add dev ens5 parent 1:1 classid 1:6 htb rate 1500mbit prio 2",
			"sudo tc class add dev ens5 parent 1:1 classid 1:7 htb rate 450mbit prio 3",
			"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 1 u32 match ip tos 0xb8 0xff match ip dst $AS_A_TS_IP_0/32 flowid 1:2",
			"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 1 u32 match ip tos 0xb8 0xff match ip dst $AS_B_TS_IP_0/32 flowid 1:3",
			"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 2 u32 match ip dst $AS_A_TS_IP_0/32 flowid 1:4",
			"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 2 u32 match ip dst $AS_B_TS_IP_0/32 flowid 1:5",
			"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 2 u32 match ip dst $LGS_IP_0/32 flowid 1:5",
			"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 2 u32 match ip dst $LGC_IP_0/32 flowid 1:6",
		},
		"AS_A_TS": {
			"sudo ip route add $AS_B_TS_IP_0/32 via $AS_A_INFRA_IP_0 dev ens5",
			"ln -sf /home/ec2-user/testnet/chrony_0_0.conf /home/ec2-user/testnet/chrony_0.conf",
			"sudo cp /home/ec2-user/testnet/chrony@.service /lib/systemd/system/chrony@0.service",
			"sudo systemctl daemon-reload",
			"sudo systemctl enable chrony@0.service",
			"sudo systemctl start chrony@0.service",
		},
		"AS_B_TS": {
			"sudo ip route add $AS_A_TS_IP_0/32 via $AS_B_INFRA_IP_0 dev ens5",
			"ln -sf /home/ec2-user/testnet/chrony_1_0.conf /home/ec2-user/testnet/chrony_1.conf",
			"sudo cp /home/ec2-user/testnet/chrony@.service /lib/systemd/system/chrony@1.service",
			"sudo systemctl daemon-reload",
			"sudo systemctl enable chrony@1.service",
			"sudo systemctl start chrony@1.service",
		},
		"LGS": {
			"sudo ip route add $LGC_IP_0/32 via $AS_B_INFRA_IP_0 dev ens5",
			"sudo cp /home/ec2-user/testnet/iperf3.service /lib/systemd/system/iperf3.service",
			"sudo systemctl daemon-reload",
			"sudo systemctl enable iperf3.service",
			"sudo systemctl start iperf3.service",
		},
		"LGC": {
			"sudo ip route add $LGS_IP_0/32 via $AS_B_INFRA_IP_0 dev ens5",
		},
	}
	setDSCPValue0Commands = map[string][]string{
		"AS_A_TS": {
			"sudo systemctl stop chrony@0.service",
			"ln -sf /home/ec2-user/testnet/chrony_0_0.conf /home/ec2-user/testnet/chrony_0.conf",
			"sudo systemctl start chrony@0.service",
			"sudo chronyc makestep",
			"sudo chronyc makestep",
			"sudo chronyc makestep",
		},
		"AS_B_TS": {
			"sudo systemctl stop chrony@1.service",
			"ln -sf /home/ec2-user/testnet/chrony_1_0.conf /home/ec2-user/testnet/chrony_1.conf",
			"sudo systemctl start chrony@1.service",
			"sudo chronyc makestep",
			"sudo chronyc makestep",
			"sudo chronyc makestep",
		},
	}
	setDSCPValue46Commands = map[string][]string{
		"AS_A_TS": {
			"sudo systemctl stop chrony@0.service",
			"ln -sf /home/ec2-user/testnet/chrony_0_46.conf /home/ec2-user/testnet/chrony_0.conf",
			"sudo systemctl start chrony@0.service",
			"sudo chronyc makestep",
			"sudo chronyc makestep",
			"sudo chronyc makestep",
		},
		"AS_B_TS": {
			"sudo systemctl stop chrony@1.service",
			"ln -sf /home/ec2-user/testnet/chrony_1_46.conf /home/ec2-user/testnet/chrony_1.conf",
			"sudo systemctl start chrony@1.service",
			"sudo chronyc makestep",
			"sudo chronyc makestep",
			"sudo chronyc makestep",
		},
	}
	runAttackCommand            = "iperf3 -c %s -u -b 5000M -t 120"
	measureOffsetsCommandFormat = "while true; do /home/ec2-user/ntimed-tool 169.254.169.123; sleep 1; done\n"
	testnetServices             = []string{
		"AS_A_INFRA",
		"AS_B_INFRA",
		"AS_A_TS",
		"AS_B_TS",
		"LGS",
		"LGC",
	}
	testnetTemplates = map[string]bool{
		"testnet/chrony_1_0.conf":  true,
		"testnet/chrony_1_46.conf": true,
	}
)

func newEC2Client() *ec2.Client {
	cfg, err := config.LoadDefaultConfig(context.TODO())
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

					for _, ni := range i.NetworkInterfaces {
						for k, a := range ni.PrivateIpAddresses {
							if k == 0 && !*a.Primary {
								panic("TODO")
							}
							fmt.Printf(", %15s", *a.PrivateIpAddress)
						}
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

func dialSSH(instanceAddr string) (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User: ec2InstanceUser,
		Auth: []ssh.AuthMethod{
			sshIdentity(os.Getenv("SSH_SECRET_ID_FILE")),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	hostAddr := fmt.Sprintf("%s:22", instanceAddr)
	var sshClient *ssh.Client
	var err error
	for i := 0; i < 60; i++ {
		sshClient, err = ssh.Dial("tcp", hostAddr, sshConfig)
		if err == nil {
			return sshClient, nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil, err
}

func createLogFile(name string) (*os.File, error) {
	err := os.MkdirAll("logs", 0755)
	if err != nil {
		return nil, err
	}
	fn := fmt.Sprintf("./logs/%s", name)
	return os.OpenFile(fn, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
}

func openLogFile(name string) (*os.File, error) {
	err := os.MkdirAll("logs", 0755)
	if err != nil {
		return nil, err
	}
	fn := fmt.Sprintf("./logs/%s", name)
	return os.OpenFile(fn, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}

func runCommand(sshClient *ssh.Client, id, command string) {
	f, err := openLogFile(id)
	if err != nil {
		log.Printf("Failed to run command %s (%s): %v", id, command, err)
		return
	}
	defer f.Close()
	sess, err := sshClient.NewSession()
	if err != nil {
		log.Printf("Failed to run command %s (%s): %v", id, command, err)
		return
	}
	defer sess.Close()
	f.WriteString(fmt.Sprintf("$ %s\n", command))
	var wg sync.WaitGroup
	sessStdout, err := sess.StdoutPipe()
	if err != nil {
		log.Printf("Failed to run command %s (%s): %v", id, command, err)
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(f, sessStdout)
	}()
	sessStderr, err := sess.StderrPipe()
	if err != nil {
		log.Printf("Failed to run command %s (%s): %v", id, command, err)
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
		log.Printf("Failed to run command %s (%s): %v", id, command, err)
	}
}

func runCommands(sshClient *ssh.Client, instanceId, instanceAddr string, commands []string) {
	id := fmt.Sprintf("%s-%s", instanceId, instanceAddr)
	for _, command := range commands {
		runCommand(sshClient, id, command)
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

func fixupServiceIPs(commands []string, data map[string]string) {
	for i := range commands {
		for _, s := range testnetServices {
			commands[i] = strings.ReplaceAll(commands[i], "$"+s+"_IP_0", data[s+"_IP_0"])
		}
	}
}

func startServices(sshClient *ssh.Client, instanceId, instanceAddr string, data map[string]string) {
	role := data[instanceId]
	commands := startServicesCommands[role]
	fixupServiceIPs(commands, data)
	runCommands(sshClient, instanceId, instanceAddr, commands)
}

func installChrony(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installChronyCommands)
}

func installNtimedTool(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installNtimedToolCommands)
}

func installIPerf3(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installIPerf3Commands)
}

func installIProute(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installIProuteCommands)
}

func addSecondaryAddrs(sshClient *ssh.Client, instanceId, instanceAddr string, data map[string]string) {
	role := data[instanceId]
	if role != "" {
		for k := 1; k < ec2InstancePrivateIpAddressCount; k++ {
			addr := data[role+"_IP_"+strconv.Itoa(k)]
			if addr != "" {
				id := fmt.Sprintf("%s-%s", instanceId, instanceAddr)
				cmd := fmt.Sprintf("sudo ip address add %s/32 dev ens5 noprefixroute || true", addr)
				runCommand(sshClient, id, cmd)
			}
		}
	}
}

func setupInstance(wg *sync.WaitGroup, instanceId, instanceAddr string, data map[string]string) {
	defer wg.Done()
	log.Printf("Connecting to instance %s...\n", instanceId)
	sshClient, err := dialSSH(instanceAddr)
	if err != nil {
		log.Printf("Failed to connect to instance %s: %v", instanceId, err)
		return
	}
	defer sshClient.Close()
	log.Printf("Installing software on instance %s...\n", instanceId)
	installIProute(sshClient, instanceId, instanceAddr)
	installIPerf3(sshClient, instanceId, instanceAddr)
	installNtimedTool(sshClient, instanceId, instanceAddr)
	installChrony(sshClient, instanceId, instanceAddr)
	log.Printf("Installing configuration files on instance %s...\n", instanceId)
	uploadTestnet(sshClient, data)
	log.Printf("Starting %s services on instance %s...\n", data[instanceId], instanceId)
	startServices(sshClient, instanceId, instanceAddr, data)
}

func setup() {
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
			KeyName:          aws.String(os.Getenv("SSH_ID")),
			MinCount:         &instanceCount,
			MaxCount:         &instanceCount,
			SecurityGroupIds: []string{os.Getenv("AWS_SECURITY_GROUP_ID")},
			SubnetId:         aws.String(os.Getenv("AWS_SUBNET_ID")),
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
		_, err = client.ModifyInstanceAttribute(
			context.TODO(),
			&ec2.ModifyInstanceAttributeInput{
				InstanceId: i.InstanceId,
				SourceDestCheck: &types.AttributeBooleanValue{
					Value: aws.Bool(false),
				},
			},
		)
		if err != nil {
			log.Fatalf("ModifyInstanceAttribute failed: %v", err)
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

	var wg sync.WaitGroup
	for instanceId, instanceAddr := range instances {
		wg.Add(1)
		go setupInstance(&wg, instanceId, instanceAddr, data)
	}
	wg.Wait()
}

func plotOffsetMeasurements(mark0, mark1 time.Duration) {
	f0, err := os.Open("./logs/offsets.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer f0.Close()

	r := csv.NewReader(f0)
	recs, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	t0, err := time.Parse(time.RFC3339, recs[0][0])
	if err != nil {
		log.Fatal(err)
	}

	minOff := math.Inf(1)
	maxOff := math.Inf(-1)

	data := make(plotter.XYs, len(recs))
	for i, rec := range recs {
		t, err := time.Parse(time.RFC3339, rec[0])
		if err != nil {
			log.Fatal(err)
		}
		off, err := strconv.ParseFloat(rec[1], 64)
		if err != nil {
			log.Fatal(err)
		}
		minOff = math.Min(minOff, off)
		maxOff = math.Max(maxOff, off)
		data[i].X = float64(t.Unix() - t0.Unix())
		data[i].Y = off
	}

	p := plot.New()
	p.X.Label.Text = "Time [s]"
	p.X.Label.Padding = vg.Points(5)
	p.Y.Label.Text = "Offset [s]"
	p.Y.Label.Padding = vg.Points(5)
	p.Y.Max = maxOff
	p.Y.Min = minOff

	p.Add(plotter.NewGrid())

	line, err := plotter.NewLine(data)
	if err != nil {
		log.Panic(err)
	}
	p.Add(line)

	if mark0 >= 0 {
		rMarker, err := plotter.NewLine(plotter.XYs{
			plotter.XY{X: mark0.Seconds(), Y: p.Y.Min},
			plotter.XY{X: mark0.Seconds(), Y: p.Y.Max},
		})
		if err != nil {
			log.Panic(err)
		}
		rMarker.Width = vg.Points(2)
		rMarker.Dashes = []vg.Length{vg.Points(2), vg.Points(2)}
		rMarker.Color = color.RGBA{R: 255, A: 255}
		p.Add(rMarker)
	}

	if mark1 >= 0 {
		gMarker, err := plotter.NewLine(plotter.XYs{
			plotter.XY{X: mark1.Seconds(), Y: p.Y.Min},
			plotter.XY{X: mark1.Seconds(), Y: p.Y.Max},
		})
		if err != nil {
			log.Panic(err)
		}
		gMarker.Width = vg.Points(2)
		gMarker.Dashes = []vg.Length{vg.Points(2), vg.Points(2)}
		gMarker.Color = color.RGBA{B: 255, A: 255}
		p.Add(gMarker)
	}

	c := vgpdf.New(8.5*vg.Inch, 3*vg.Inch)
	c.EmbedFonts(true)
	dc := draw.New(c)
	dc = draw.Crop(dc, 1*vg.Millimeter, -1*vg.Millimeter, 1*vg.Millimeter, -1*vg.Millimeter)

	p.Draw(dc)

	f1, err := os.Create("./logs/offsets.pdf")
	if err != nil {
		log.Fatal(err)
	}
	defer f1.Close()

	_, err = c.WriteTo(f1)
	if err != nil {
		log.Fatal(err)
	}
}

func runAttack(instanceId, instanceAddr, targetAddr string) {
	sshClient, err := dialSSH(instanceAddr)
	if err != nil {
		log.Printf("Failed to connect to instance %s: %v", instanceAddr, err)
		return
	}
	defer sshClient.Close()
	runCommand(sshClient, instanceId, fmt.Sprintf(runAttackCommand, targetAddr))
}

func startOffsetMeasurements(wg *sync.WaitGroup, instanceAddr string) (
	*ssh.Client, *ssh.Session, *os.File, error) {
	sshClient, err := dialSSH(instanceAddr)
	if err != nil {
		return nil, nil, nil, err
	}

	sshSession, err := sshClient.NewSession()
	if err != nil {
		sshClient.Close()
		return nil, nil, nil, err
	}

	logFile, err := createLogFile("offsets.csv")
	if err != nil {
		sshSession.Close()
		sshClient.Close()
		return nil, nil, nil, err
	}

	sessStdout, err := sshSession.StdoutPipe()
	if err != nil {
		logFile.Close()
		sshSession.Close()
		sshClient.Close()
		return nil, nil, nil, err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(logFile, sessStdout)
	}()
	sessStderr, err := sshSession.StderrPipe()
	if err != nil {
		logFile.Close()
		sshSession.Close()
		sshClient.Close()
		return nil, nil, nil, err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(logFile, sessStderr)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = sshSession.Run(measureOffsetsCommandFormat)
		if err != nil {
			var exitError *ssh.ExitError
			if !errors.As(err, &exitError) || exitError.ExitStatus() != 143 {
				log.Printf("Failed to measure offsets on instance %s: %v", instanceAddr, err)
			}
		}
	}()

	return sshClient, sshSession, logFile, nil
}

func run() {
	instanceIds := map[string]string{}
	instanceAddrs := map[string]string{}

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
			if *i.State.Code == ec2InstanceStateRunning {
				for _, t := range i.Tags {
					if *t.Key == "Name" && *t.Value == ec2InstanceName {
						for _, tt := range i.Tags {
							if *tt.Key == "Role" {
								switch *tt.Value {
								case "LGC", "AS_A_TS", "AS_B_TS":
									if i.InstanceId != nil {
										instanceIds[*tt.Value] = *i.InstanceId
									}
									if i.PublicIpAddress != nil {
										instanceAddrs[*tt.Value] = *i.PublicIpAddress
									}
								case "LGS":
									if i.InstanceId != nil {
										instanceIds[*tt.Value] = *i.InstanceId
									}
									if i.PrivateIpAddress != nil {
										instanceAddrs[*tt.Value] = *i.PrivateIpAddress
									}
								}
							}
						}
					}
				}
			}
		}
	}

	sshClientAS_A_TS, err := dialSSH(instanceAddrs["AS_A_TS"])
	if err != nil {
		log.Printf("Failed to connect to instance %s: %v", instanceAddrs["AS_A_TS"], err)
		return
	}
	defer sshClientAS_A_TS.Close()
	sshClientAS_B_TS, err := dialSSH(instanceAddrs["AS_B_TS"])
	if err != nil {
		log.Printf("Failed to connect to instance %s: %v", instanceAddrs["AS_B_TS"], err)
		return
	}
	defer sshClientAS_B_TS.Close()

	var wg sync.WaitGroup
	sshClient, sshSession, logFile, err := startOffsetMeasurements(&wg, instanceAddrs["AS_B_TS"])
	if err != nil {
		log.Fatalf("startOffsetMeasurements failed: %v", err)
	}

	t0 := time.Now()

	log.Printf("Preparing 1st attack [ca. %ds]...", attackPreparation/time.Second)
	runCommands(sshClientAS_A_TS, instanceIds["AS_A_TS"], instanceAddrs["AS_A_TS"],
		setDSCPValue0Commands["AS_A_TS"])
	runCommands(sshClientAS_B_TS, instanceIds["AS_B_TS"], instanceAddrs["AS_B_TS"],
		setDSCPValue0Commands["AS_B_TS"])
	time.Sleep(attackPreparation)

	m0 := time.Since(t0)

	log.Printf("Running 1st attack [ca. %ds]...", attackDuration/time.Second)
	go runAttack(instanceIds["LGC"], instanceAddrs["LGC"], instanceAddrs["LGS"])
	time.Sleep(attackDuration)

	log.Printf("Preparing 2nd attack [ca. %ds]...", attackPreparation/time.Second)
	runCommands(sshClientAS_A_TS, instanceIds["AS_A_TS"], instanceAddrs["AS_A_TS"],
		setDSCPValue46Commands["AS_A_TS"])
	runCommands(sshClientAS_B_TS, instanceIds["AS_B_TS"], instanceAddrs["AS_B_TS"],
		setDSCPValue46Commands["AS_B_TS"])
	time.Sleep(attackPreparation)

	m1 := time.Since(t0)

	log.Printf("Running 2nd attack [ca. %ds]...", attackDuration/time.Second)
	go runAttack(instanceIds["LGC"], instanceAddrs["LGC"], instanceAddrs["LGS"])
	time.Sleep(attackDuration)

	log.Print("Finishing test run...")
	err = sshSession.Signal(ssh.SIGTERM)
	if err == nil {
		wg.Wait()
	}
	sshSession.Close()
	sshClient.Close()
	logFile.Close()

	plotOffsetMeasurements(m0, m1)
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
	runFlags := flag.NewFlagSet("test", flag.ExitOnError)

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
		setup()
	case "run":
		err := runFlags.Parse(os.Args[2:])
		if err != nil || runFlags.NArg() != 0 {
			exitWithUsage()
		}
		run()
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
