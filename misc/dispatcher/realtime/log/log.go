package log

import (
	"golang.org/x/sys/unix"
)

func WriteUint64(fd int, x uint64) {
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

func WriteBytes(fd int, x []byte) {
	unix.Write(fd, x)
}

func WriteString(fd int, x string) {
	unix.Write(fd, []byte(x))
}

func WriteLn(fd int) {
	unix.Write(fd, []byte{'\n'})
}
