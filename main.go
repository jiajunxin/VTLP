package main

import (
	"runtime"

	"github.com/PoMoDE/protocol"
	"github.com/PoMoDE/snark"
	//"github.com/PoMoDE/protocol"
)

func main() {
	//protocol.ManualBench(1000000)
	//snark.GenSigOffloadTestCircuit(protocol.RSAExpSetup(), protocol.TrustedSetup())
	snark.TestOffloadSig()
	protocol.RSAExpSetup()
	//_ = snark.GenVLTPTestSet(nil, protocol.TrustedSetup())
	runtime.GC()
	//snark.TestRSAOffload()

	return
}
