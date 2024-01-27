package main

import (
	"runtime"

	"github.com/PoMoDE/snark"
	//"github.com/PoMoDE/protocol"
)

func main() {
	//protocol.ManualBench(1000000)
	//protocol.RSAExpSetup()
	//_ = snark.GenVLTPTestSet(nil, protocol.TrustedSetup())
	snark.TestRSAOffload()
	runtime.GC()

	return
}
