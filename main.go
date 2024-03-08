package main

import (
	"runtime"

	"github.com/PoMoDE/protocol"
	"github.com/PoMoDE/snark"
)

func main() {

	snark.GenSigOffloadTestCircuit(protocol.RSAExpSetup(), protocol.TrustedSetup())
	protocol.RSAExpSetup()
	snark.TestOffloadSig()
	snark.TestOffloadZKSig()
	snark.TestRSAOffload()
	runtime.GC()

	return
}
