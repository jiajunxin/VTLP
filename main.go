package main

import (
	"runtime"

	"github.com/VTLP/protocol"
	"github.com/VTLP/snark"
)

func main() {

	snark.GenSigOffloadTestCircuit(protocol.RSAExpSetup(), protocol.TrustedSetup())
	protocol.RSAExpSetup()
	snark.TestOffloadSig()
	snark.TestOffloadZKSig()
	snark.TestVTLP()
	runtime.GC()
}
