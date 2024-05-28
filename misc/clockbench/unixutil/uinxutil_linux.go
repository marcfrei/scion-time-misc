package unixutil

import (
	"golang.org/x/sys/unix"
)

func NsecToNsecTimeval(nsec int64) unix.Timeval {
	sec := nsec / 1e9
	nsec = nsec % 1e9
	// The field unix.Timeval.Usec must always be non-negative.
	if nsec < 0 {
		sec -= 1
		nsec += 1e9
	}
	return unix.Timeval{
		Sec:  sec,
		Usec: nsec,
	}
}

// In struct timex, freq, ppsfreq, and stabil are (scaled) ppm (parts per
// million) with a 16-bit fractional part, which means that a value of 1 in one
// of those fields actually means 2^-16 ppm, and 2^16=65536 is 1 ppm. This is
// the case for both input values (in the case of freq) and output values.
// See, https://www.man7.org/linux/man-pages/man2/adjtimex.2.html

func FreqToScaledPPM(freq float64) int64 {
	return int64(freq * 65536 * 1e6)
}

func FreqFromScaledPPM(scaledPPM int64) float64 {
	return float64(scaledPPM) / (65536.0 * 1e6)
}
