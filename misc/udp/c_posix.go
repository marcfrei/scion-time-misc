package main

import (
	_ "unsafe"

	"net/netip"
	"os"
	"runtime"
	"runtime/pprof"	
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

//go:linkname RecvmsgInet4 syscall.recvmsgInet4
//go:noescape
func RecvmsgInet4(fd int, p, oob []byte, flags int, from *syscall.SockaddrInet4) (n, oobn int, recvflags int, err error)

//go:linkname SendtoInet4 syscall.sendtoInet4
//go:noescape
func SendtoInet4(fd int, p []byte, flags int, to *syscall.SockaddrInet4) (err error)

var (
	lmu sync.Mutex
	buf [1024]byte
)

func logUint64(f *os.File, x uint64) {
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
	f.Write(b[:n])
}

func logBytes(f *os.File, x []byte) {
	f.Write(x)
}

func logString(f *os.File, x string) {
	f.Write([]byte(x))
}

func logLn(f *os.File) {
	f.Write([]byte{'\n'})
}

func logError(f *os.File, label string, err error) {
	lmu.Lock()
	defer lmu.Unlock()
	logString(f, label)
	logString(f, ": ")
	logString(f, err.Error())
	logLn(f)
}

func logMsg(f *os.File, buf []byte, n int, oob []byte, oobn int, flags int, peer *syscall.SockaddrInet4) {
	lmu.Lock()
	defer lmu.Unlock()
	logString(f, "n: ")
	logUint64(f, uint64(n))
	logLn(f)
	logString(f, "oobn: ")
	logUint64(f, uint64(oobn))
	logLn(f)
	logString(f, "flags: ")
	logUint64(f, uint64(flags))
	logLn(f)
	logString(f, "peer: ")
	logUint64(f, uint64(peer.Addr[0]))
	logString(f, ".")
	logUint64(f, uint64(peer.Addr[1]))
	logString(f, ".")
	logUint64(f, uint64(peer.Addr[2]))
	logString(f, ".")
	logUint64(f, uint64(peer.Addr[3]))
	logString(f, ":")
	logUint64(f, uint64(peer.Port))
	logLn(f)
	logString(f, "buf: ")
	logBytes(f, buf[:n])
	logLn(f)
	logLn(f)
}

func logMemStats(f *os.File) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	lmu.Lock()
	defer lmu.Unlock()
	logString(f, "TotalAlloc: ")
	logUint64(f, uint64(m.TotalAlloc))
	logLn(f)
	logString(f, "Mallocs: ")
	logUint64(f, uint64(m.Mallocs))
	logLn(f)
	logString(f, "Frees: ")
	logUint64(f, uint64(m.Frees))
	logLn(f)
	logString(f, "NumGC: ")
	logUint64(f, uint64(m.NumGC))
	logLn(f)
	logLn(f)
}

func logThreadProfile(f *os.File, p *pprof.Profile) {
	lmu.Lock()
	defer lmu.Unlock()
	logString(f, "Thread Count: ")
	logUint64(f, uint64(p.Count()))
	logLn(f)
	logLn(f)
}

func monitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	threadprofile := pprof.Lookup("threadcreate")
	for {
		select {
		case <-ticker.C:
			logMemStats(os.Stderr)
			logThreadProfile(os.Stderr, threadprofile)
		}
	}
}

func exchangeMsg(msg []byte, raddr *syscall.SockaddrInet4) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		logError(os.Stderr, "socket creation failed: ", err)
		os.Exit(1)
	}
	defer unix.Close(fd) 
	err = SendtoInet4(fd, msg, 0, raddr)
	if err != nil {
		logError(os.Stderr, "send failed: ", err)
		return
	}
	var raddr1 syscall.SockaddrInet4
	n, oobn, flags, err := RecvmsgInet4(fd, buf[:], nil, 0, &raddr1)
	if err != nil {
		logError(os.Stderr, "recv failed: ", err)
		return
	}
	_, _, _ = n, oobn, flags
	// logMsg(os.Stdout, buf[:], n, nil, oobn, flags, &raddr1)
}

func main() {
	go monitor()
	ap, err := netip.ParseAddrPort(os.Args[1])
	if err != nil {
		logError(os.Stderr, "unexpected remote address: ", err)
		os.Exit(1)
	}
	raddr0 := syscall.SockaddrInet4{
		Addr: ap.Addr().As4(),
		Port: int(ap.Port()),
	}
	msg := []byte(os.Args[2])
	sg := make(chan struct{})
	for i := 0; i != 1_000; i++ {
		go func() {
			<-sg
			for j := 0; j != 5; j++ {
				exchangeMsg(msg, &raddr0)
			}
		}()
	}
	time.Sleep(16 * time.Second)
	close(sg)
	select {}
}

// GODEBUG='allocfreetrace=1' ./c_posix 127.0.0.1:10123 xyz
