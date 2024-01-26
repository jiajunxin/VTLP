package main

import (
	"runtime"

	"github.com/PoMoDE/snark"
	//"github.com/PoMoDE/protocol"
)

func main() {
	//protocol.ManualBench(1000000)

	snark.TestRSAOffload()
	runtime.GC()

	return
}
