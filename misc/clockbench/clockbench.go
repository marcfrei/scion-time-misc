package main

import (
	"log"

	"example.com/clockbench/clocks"
)

func main() {
	clk := clocks.SystemClock{}
	log.Print(clk.Now())
}
