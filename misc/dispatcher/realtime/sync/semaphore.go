package sync

import (
	"golang.org/x/sys/unix"
)

type Semaphore struct {
	valid bool
	fd    int
}

func NewSemaphore(initval uint) *Semaphore {
	fd, err := unix.Eventfd(initval, unix.EFD_NONBLOCK|unix.EFD_SEMAPHORE)
	if err != nil {
		panic("sync.Semaphore: unix.Eventfd failed")
	}
	return &Semaphore{
		valid: true,
		fd:    fd,
	}
}

func (s *Semaphore) Fd() int {
	if !s.valid {
		panic("sync.Semaphore: use of uninitialized semaphore")
	}
	return s.fd
}

func (s *Semaphore) Acquire() bool {
	if !s.valid {
		panic("sync.Semaphore: use of uninitialized semaphore")
	}
	val := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	for {
		n, err := unix.Read(s.fd, val)
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return false
		}
		if err != nil || n != 8 ||
			val[0] != 1 || val[1] != 0 || val[2] != 0 || val[3] != 0 ||
			val[4] != 0 || val[5] != 0 || val[6] != 0 || val[7] != 0 {
			panic("sync.Semaphore: unix.Read failed")
		}
		return true
	}
}

func (s *Semaphore) Release() {
	if !s.valid {
		panic("sync.Semaphore: use of uninitialized semaphore")
	}
	val := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	for {
		n, err := unix.Write(s.fd, val)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n != len(val) {
			panic("sync.Semaphore: unix.Write failed")
		}
		return
	}
}
