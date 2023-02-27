package main

import (
	_ "unsafe"

	"net/netip"
	"os"
	"runtime"
	"runtime/pprof"
	_ "sync"
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
	stdout = int(os.Stdout.Fd()) 
	stderr = int(os.Stderr.Fd()) 

	// lmu sync.Mutex

	raddr *syscall.SockaddrInet4
	msg []byte

	epfd int
	buf [1024]byte

	fds [16384]int
	numFD int
)

func logUint64(fd int, x uint64) {
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
	unix.Write(fd, b[:n])
}

func logBytes(fd int, x []byte) {
	unix.Write(fd, x)
}

func logString(fd int, x string) {
	unix.Write(fd, []byte(x))
}

func logLn(fd int) {
	unix.Write(fd, []byte{'\n'})
}

func logError(fd int, label string, err error) {
	// lmu.Lock()
	// defer lmu.Unlock()
	logString(fd, label)
	logString(fd, ": ")
	logString(fd, err.Error())
	logLn(fd)
}

func logMsg(fd int, buf []byte, n int, oob []byte, oobn int, flags int, peer *syscall.SockaddrInet4) {
	// lmu.Lock()
	// defer lmu.Unlock()
	logString(fd, "n: ")
	logUint64(fd, uint64(n))
	logLn(fd)
	logString(fd, "oobn: ")
	logUint64(fd, uint64(oobn))
	logLn(fd)
	logString(fd, "flags: ")
	logUint64(fd, uint64(flags))
	logLn(fd)
	logString(fd, "peer: ")
	logUint64(fd, uint64(peer.Addr[0]))
	logString(fd, ".")
	logUint64(fd, uint64(peer.Addr[1]))
	logString(fd, ".")
	logUint64(fd, uint64(peer.Addr[2]))
	logString(fd, ".")
	logUint64(fd, uint64(peer.Addr[3]))
	logString(fd, ":")
	logUint64(fd, uint64(peer.Port))
	logLn(fd)
	logString(fd, "buf: ")
	logBytes(fd, buf[:n])
	logLn(fd)
	logLn(fd)
}

func logMemStats(fd int) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// lmu.Lock()
	// defer lmu.Unlock()
	logString(fd, "TotalAlloc: ")
	logUint64(fd, uint64(m.TotalAlloc))
	logLn(fd)
	logString(fd, "Mallocs: ")
	logUint64(fd, uint64(m.Mallocs))
	logLn(fd)
	logString(fd, "Frees: ")
	logUint64(fd, uint64(m.Frees))
	logLn(fd)
	logString(fd, "NumGC: ")
	logUint64(fd, uint64(m.NumGC))
	logLn(fd)
	logLn(fd)
}

func logThreadProfile(fd int, p *pprof.Profile) {
	// lmu.Lock()
	// defer lmu.Unlock()
	logString(fd, "Thread Count: ")
	logUint64(fd, uint64(p.Count()))
	logLn(fd)
	logLn(fd)
}

func sleep(sec int64) {
	var tv unix.Timeval
	tv.Sec = sec
	unix.Select(0, nil, nil, nil, &tv)
}

func monitor() {
	threadprofile := pprof.Lookup("threadcreate")
	for {
		sleep(3)
		logMemStats(stderr)
		logThreadProfile(stderr, threadprofile)
	}
}

func handleAvailableForWrite(fd int) {
	err := SendtoInet4(fd, msg, 0, raddr)
	if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
		return
	} else if err != nil {
		logError(stderr, "send failed: ", err)
		return
	}
	// lmu.Lock()
	// logString(stdout, "sent: ")
	// logUint64(stdout, uint64(fd))
	// logLn(stdout)
	// lmu.Unlock()
	var event unix.EpollEvent
	event.Events = unix.EPOLLIN|unix.EPOLLONESHOT
	event.Fd = int32(fd)
	err = unix.EpollCtl(epfd, unix.EPOLL_CTL_MOD, fd, &event)
	if err != nil {
		logError(stderr, "EpollCtl failed: ", err)
		os.Exit(1)
	}
}

func handleAvailableForRead(fd int) {
	var raddr1 syscall.SockaddrInet4
	n, oobn, flags, err := RecvmsgInet4(fd, buf[:], nil, 0, &raddr1)
	if err != nil {
		logError(stderr, "recv failed: ", err)
		return
	}
	_, _, _ = n, oobn, flags
	// logMsg(stdout, buf[:], n, nil, oobn, flags, &raddr1)
	unix.Close(fd)
	// lmu.Lock()
	// logString(stdout, "completed: ")
	// logUint64(stdout, uint64(fd))
	// logLn(stdout)
	// lmu.Unlock()
}

func exchangeMsg() {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.O_NONBLOCK, 0)
	if err != nil {
		logError(stderr, "socket creation failed: ", err)
		return
	}
	fds[numFD] = fd
	numFD++
	err = unix.SetNonblock(fd, true)
	if err != nil {
		logError(stderr, "set socket nonblocking failed: ", err)
		os.Exit(1)
	}
	var event unix.EpollEvent
	event.Events = unix.EPOLLOUT|unix.EPOLLONESHOT
	event.Fd = int32(fd)
	err = unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, &event)
	if err != nil {
		logError(stderr, "EpollCtl failed: ", err)
		os.Exit(1)
	}
}

func pollEvents(sg chan struct{}) {
	runtime.LockOSThread()
	var events [16]unix.EpollEvent
	<-sg
	for {
		n, err := unix.EpollWait(epfd, events[:], -1)
		if err == unix.EINTR {
			continue
		} else if err != nil {
			logError(stderr, "EpollWait failed: ", err)
			os.Exit(1)
		}
		for i := 0; i != n; i++ {
			if int(events[i].Events) == syscall.EPOLLIN {
				handleAvailableForRead(int(events[i].Fd))
			} else if int(events[i].Events) == syscall.EPOLLOUT {
				handleAvailableForWrite(int(events[i].Fd))
			} else {
				logString(stderr, "Events: ")
				logUint64(stderr, uint64(events[i].Events))
				logLn(stderr)
				// os.Exit(1)
			}
		}
	}
}

func main() {
	go monitor()
	var err error
	epfd, err = unix.EpollCreate1(0)
	if err != nil {
		logError(stderr, "epoll_create1 failed: ", err)
		os.Exit(1)
	}
	defer syscall.Close(epfd)

	ap, err := netip.ParseAddrPort(os.Args[1])
	if err != nil {
		logError(stderr, "unexpected remote address: ", err)
		os.Exit(1)
	}
	raddr0 := syscall.SockaddrInet4{
		Addr: ap.Addr().As4(),
		Port: int(ap.Port()),
	}
	raddr = &raddr0
	msg = []byte(os.Args[2])
	sg := make(chan struct{})
	for i, n := 0, runtime.NumCPU(); i != n; i++ {
		go pollEvents(sg)
	}
	sleep(16)
	close(sg)
	for {
		sleep(16)
		for i := 0; i != numFD; i++ {
			unix.Close(fds[i])
		}
		numFD = 0
		for i := 0; i != 2_000; i++ {
				for j := 0; j != 5; j++ {
					exchangeMsg()
				}
		}
	}
	select {}
}

// GODEBUG='allocfreetrace=1' ./c_epoll 127.0.0.1:10123 xyz
