package main

import (
	"os"
	"sync"
	"golang.org/x/sys/unix"
)

var token sync.Mutex

func logString(fd int, x string) {
	unix.Write(fd, []byte(x))
}

func logLn(fd int) {
	unix.Write(fd, []byte{'\n'})
}

func sleep(nsec int64) {
	var ts unix.Timespec
	ts.Nsec = nsec
	unix.Nanosleep(&ts, nil)
}

func lock(m *sync.Mutex) {
	success := m.TryLock()
	for !success {
		sleep(0)
		success = m.TryLock()
	}
}

func g(s string) {
	lock(&token)
	defer token.Unlock()
	stdout := int(os.Stdout.Fd())
	logString(stdout, s)
	logLn(stdout)
}

func f(s string) {
	for {
		g(s)
		sleep(100_000_000)
	}
}

func main() {
	go f("A")
	go f("B")
	select {}
}

/*
GODEBUG='allocfreetrace=1' ./sync
*/
