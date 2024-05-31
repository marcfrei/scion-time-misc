package main

import (
	"log"
	"log/slog"
	"time"

	"example.com/clockbench/clocks"
)

func main() {
	clk := clocks.SystemClock{Log: slog.Default()}
	t0 := clk.Now()
	f0 := clk.Frequency()
	log.Printf("%v: %v", t0.Sub(t0), f0)
	// clk.Adjust(-10*time.Millisecond, 1*time.Minute, f0)
	for {
		t := clk.Now()
		f := clk.Frequency()
		log.Printf("%v: %v", t.Sub(t0), f)
		if t.After(t0.Add(63 * time.Second)) {
			break
		}
		clk.Sleep(100 * time.Millisecond)
	}
}
