package main

import (
	"runtime"

	"github.com/PoMoDE/protocol"
)

func main() {
	protocol.ManualBench(1000000)
	runtime.GC()
	return
}
