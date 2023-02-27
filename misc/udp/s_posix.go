package main

import (
	_ "unsafe"

	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"

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

	laddr unix.SockaddrInet4
	raddr syscall.SockaddrInet4
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

func sleep(sec int64) {
	var tv unix.Timeval
	tv.Sec = sec
	unix.Select(0, nil, nil, nil, &tv)
}

func monitor() {
	for {
		sleep(3)
		logMemStats(os.Stderr)
	}
}

func main() {
	go monitor()
	ap, err := netip.ParseAddrPort(os.Args[1])
	if err != nil {
		logError(os.Stderr, "unexpected local address: ", err)
		os.Exit(1)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		logError(os.Stderr, "socket creation failed: ", err)
		os.Exit(1)
	}
	defer unix.Close(fd)
	laddr = unix.SockaddrInet4{
		Port: int(ap.Port()),
	}
	err = unix.Bind(fd, &laddr)
	if err != nil {
		logError(os.Stderr, "bind failed: ", err)
		os.Exit(1)
	}
	for {
		n, oobn, flags, err := RecvmsgInet4(fd, buf[:], nil, 0, &raddr)
		if err != nil {
			logError(os.Stderr, "recv failed: ", err)
			continue
		}
		// time.Sleep(1 * time.Millisecond)
		_, _ = oobn, flags
		// logMsg(os.Stdout, buf[:], n, nil, oobn, flags, &raddr)
		err = SendtoInet4(fd, buf[:n], 0, &raddr)
		if err != nil {
			logError(os.Stderr, "send failed: ", err)
			continue
		}
	}
}

// GODEBUG='allocfreetrace=1' ./s_posix 0.0.0.0:10123
