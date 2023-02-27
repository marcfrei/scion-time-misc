package main

import (
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"
)

func logUint64(x uint64) {
	b := make([]byte, 20)
	n := 0
	for {
		b[n] = '0' + byte(x%10)
		n++
		x /= 10
		if x == 0 {
			break
		}
	}
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	os.Stdout.Write(b[:n])
}

func logString(x string) {
	os.Stdout.Write([]byte(x))
}

func logLn() {
	os.Stdout.Write([]byte{'\n'})
}

func logMemStats() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	logString("TotalAlloc: ")
	logUint64(m.TotalAlloc)
	logLn()
	logString("Mallocs: ")
	logUint64(m.Mallocs)
	logLn()
	logString("Frees: ")
	logUint64(m.Frees)
	logLn()
	logString("NumGC: ")
	logUint64(uint64(m.NumGC))
	logLn()
}

func main() {
	useUDPAddrPort := len(os.Args) > 2 && os.Args[1] == "-udpAddrPort"
	var addrArg int
	if useUDPAddrPort {
		addrArg = 2
	} else {
		addrArg = 1
	}
	udpAddr, err := net.ResolveUDPAddr("udp", os.Args[addrArg])
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 4096)
	t0 := time.Now()
	for {
		var n, m int
		var addr net.Addr
		var udpAddrPort netip.AddrPort
		if useUDPAddrPort {
			n, udpAddrPort, err = conn.ReadFromUDPAddrPort(buf)
		} else {
			n, addr, err = conn.ReadFrom(buf)
		}
		if err != nil {
			log.Println(err)
			continue
		}
		if useUDPAddrPort {
			log.Println(udpAddrPort, n, string(buf[:n]))
		} else {
			log.Println(addr, n, string(buf[:n]))
		}
		t1 := time.Now()
		if t1.Sub(t0) > 1*time.Second {
			logMemStats()
			t0 = time.Now()
		}
		if useUDPAddrPort {
			m, err = conn.WriteToUDPAddrPort(buf[:n], udpAddrPort)
		} else {
			m, err = conn.WriteTo(buf[:n], addr)
		}
		if err != nil {
			log.Println(err)
			continue
		}
		if m != n {
			log.Println("n:", n, "m:", m)
			continue
		}
	}
}

// ./s :10123
// GODEBUG='allocfreetrace=1' ./s -udpAddrPort :10123
