package main

import (
	"fmt"
	"time"

	"example.com/scion-time/go/net/ntp"
	fbntp "github.com/facebook/time/ntp/protocol"
)

func toNtpTime(t time.Time) ntp.Time64 {
	// Excerpt from https://github.com/beevik/ntp
	// Copyright 2015-2017 Brett Vickers.
	const nanoPerSec = 1000000000
	var ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

	nsec := uint64(t.Sub(ntpEpoch))
	sec := nsec / nanoPerSec
	nsec = uint64(nsec-sec*nanoPerSec) << 32
	frac := uint64(nsec / nanoPerSec)
	if nsec%nanoPerSec >= nanoPerSec/2 {
		frac++
	}
	return ntp.Time64{
		Seconds:  uint32(sec),
		Fraction: uint32(frac),
	}
}

func do(t time.Time) {
	t0 := toNtpTime(t)
	fmt.Printf("Time64FromTime sec: %v, frac: %v\n", t0.Seconds, t0.Fraction)

	t1Seconds, t1Fraction := fbntp.Time(t)
	fmt.Printf("Time64FromTime sec: %v, frac: %v\n", t1Seconds, t1Fraction)

	t2 := ntp.Time64FromTime(t)
	fmt.Printf("Time64FromTime sec: %v, frac: %v\n", t2.Seconds, t2.Fraction)
}

func main() {
	do(time.Now())
	fmt.Println()

	do(time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC))
	fmt.Println()

	do(time.Date(1900, 1, 1, 0, 0, 0, 1, time.UTC))
	fmt.Println()

	do(time.Date(1900, 1, 1, 0, 0, 0, 999_999_999, time.UTC))
	fmt.Println()

	do(time.Date(1899, 12, 31, 0, 0, 0, 0, time.UTC))
	fmt.Println()

	do(time.Date(2036, 2, 7, 0, 0, 0, 0, time.UTC))
	fmt.Println()

	do(time.Date(2036, 2, 8, 0, 0, 0, 0, time.UTC))
	fmt.Println()

	do(time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC))
	fmt.Println()

	do(time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC))
	fmt.Println()
}
