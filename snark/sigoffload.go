package snark

import (
	"fmt"
	"math/big"
	"os"
	"runtime"
	"time"

	fiatshamir "github.com/PoMoDE/fiat-shamir"
	"github.com/PoMoDE/protocol"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var (
	big1 = big.NewInt(1)
	// Min2048 is set to 2^2047
	Min2048 = big.NewInt(0)
)

func init() {
	_ = Min2048.Lsh(big1, 2047)
}

func SetupOffloadSig() {
	circuit := InitCircuitZKSig()
	fmt.Println("Start Compiling")
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, circuit) //, frontend.IgnoreUnconstrainedInputs()
	if err != nil {
		panic(err)
	}
	fmt.Println("Finish Compiling")
	fmt.Println("Number of constrains: ", r1cs.GetNbConstraints())

	fileName := OffloadZKSigPrefix + "_original"
	err = groth16.SetupLazyWithDump(r1cs, fileName)
	if err != nil {
		panic(err)
	}
	fmt.Println("Finish Setup")
}

func SetupOffloadZKSig() {
	circuit := InitCircuitZKSig()
	fmt.Println("Start Compiling")
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, circuit) //, frontend.IgnoreUnconstrainedInputs()
	if err != nil {
		panic(err)
	}
	fmt.Println("Finish Compiling")
	fmt.Println("Number of constrains: ", r1cs.GetNbConstraints())

	fileName := OffloadZKSigPrefix + "_original"
	err = groth16.SetupLazyWithDump(r1cs, fileName)
	if err != nil {
		panic(err)
	}
	fmt.Println("Finish Setup")
}

func isOffloadSigCircuitExist() bool {
	fileName := OffloadSigPrefix + "_original.vk.save"
	_, err := os.Stat(fileName)
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}

func isOffloadZKSigCircuitExist() bool {
	fileName := OffloadZKSigPrefix + "_original.vk.save"
	_, err := os.Stat(fileName)
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}

// GenSigOffloadTestCircuit generates a set of values for test purpose.
func GenSigOffloadTestCircuit(setup *protocol.RSAExpProof, trustedSetup *protocol.Setup) (*SigCircuit, *SigCircuit) {
	var ret, retPub SigCircuit
	hFunc := hash.MIMC_BN254.New()
	msg := make([]byte, 32)
	msg[0] = 0x0d
	hFunc.Write(msg)
	hashOut := hFunc.Sum(nil)
	var sig, hashBig, hashSum, temp big.Int
	hashBig.SetBytes(hashOut)
	hashSum.Add(Min2048, &hashBig)
	sig.Exp(&hashSum, setup.D, setup.RSAMod)
	temp.Exp(&sig, setup.E, setup.RSAMod)
	// We are simplily checking the same message and signaure for many rounds
	if temp.Cmp(&hashSum) != 0 {
		fmt.Println("the RSA signature check fails in GenSigOffloadTestCircuit")
	}

	var acc, challenge, remainder, prod, deltamod big.Int
	prod.SetInt64(1)
	for i := 0; i < SetSize; i++ {
		prod.Mul(&prod, &hashSum)
	}
	acc.Exp(trustedSetup.G, &prod, trustedSetup.N)
	// We should generate a commitment of x here and input into as part of the transcript. However, this version of gnark does not support CP-SNARK.
	transcript := fiatshamir.InitTranscript([]string{setup.Base.String(), setup.RSAMod.String(), trustedSetup.G.String(), trustedSetup.N.String(), acc.String()}, fiatshamir.Max252)
	challenge.Set(transcript.GetPrimeChallengeUsingTranscript())
	remainder.Mod(&prod, &challenge)
	deltamod.Mod(Min2048, &challenge)

	ret.ChallengeL = challenge
	retPub.ChallengeL = challenge
	ret.RemainderR = remainder
	retPub.RemainderR = remainder
	ret.DeltaModL = deltamod
	retPub.DeltaModL = deltamod
	ret.Messages = make([]frontend.Variable, SetSize)
	ret.HashOutputs = make([]frontend.Variable, SetSize)
	retPub.Messages = make([]frontend.Variable, SetSize)
	retPub.HashOutputs = make([]frontend.Variable, SetSize)
	for i := 0; i < SetSize; i++ {
		ret.Messages[i] = msg
		ret.HashOutputs[i] = hashBig
	}

	return &ret, &retPub
}

// TestRSAOffload is temporarily used for test purpose
func TestOffloadSig() {
	if !isOffloadSigCircuitExist() {
		fmt.Println("Circuit haven't been compiled for RSAExpOffload. Start compiling.")
		startingTime := time.Now().UTC()
		SetupOffloadSig()
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Generating a SNARK circuit for RSAExpOffload, takes [%.3f] Seconds \n", duration.Seconds())
	} else {
		fmt.Println("Circuit have already been compiled for test purpose.")
	}
	fullcircuit, publiccircuit := GenSigOffloadTestCircuit(protocol.RSAExpSetup(), protocol.TrustedSetup())
	runtime.GC()
	fmt.Println("Start Proving")
	fileName := OffloadSigPrefix + "_original"
	startingTime := time.Now().UTC()
	pk, err := groth16.ReadSegmentProveKey(fileName)
	if err != nil {
		fmt.Println("error while ReadSegmentProveKey")
		return
	}
	r1cs, err := groth16.LoadR1CSFromFile(fileName)
	if err != nil {
		fmt.Println("error while LoadR1CSFromFile")
		return
	}
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Loading a SNARK circuit and proving key for OffloadingSignatures, takes [%.3f] Seconds \n", duration.Seconds())

	witness, err := frontend.NewWitness(fullcircuit, ecc.BN254)
	if err != nil {
		fmt.Println("error while AssignCircuit")
		return
	}
	runtime.GC()
	startingTime = time.Now().UTC()
	proof, err := groth16.ProveRoll(r1cs, pk[0], pk[1], witness, fileName, backend.IgnoreSolverError()) // backend.IgnoreSolverError() can be used for testing
	if err != nil {
		fmt.Println("error while ProveRoll")
		return
	}
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generating a SNARK proof for RSA exponentiation Offloading, takes [%.3f] Seconds \n", duration.Seconds())
	runtime.GC()
	vk, err := LoadVerifyingKey(fileName)
	if err != nil {
		panic("r1cs init error")
	}
	runtime.GC()
	publicWitness, err := frontend.NewWitness(publiccircuit, ecc.BN254, frontend.PublicOnly())
	if err != nil {
		fmt.Println("Error generating NewWitness in GenPublicWitness")
		return
	}
	startingTime = time.Now().UTC()
	err = groth16.Verify(proof, vk, publicWitness)
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Verifying a SNARK proof for RSAExpOffload, takes [%.3f] Seconds \n", duration.Seconds())
	if err != nil {
		fmt.Println("verify error = ", err)
		return
	}
	return
}

// GenSigOffloadTestCircuit generates a set of values for test purpose.
func GenZKSigOffloadTestCircuit(setup *protocol.RSAExpProof, trustedSetup *protocol.Setup) (*ZKSigCircuit, *ZKSigCircuit) {
	var ret, retPub ZKSigCircuit
	hFunc := hash.MIMC_BN254.New()
	msg := make([]byte, 32)
	msg[0] = 0x0d
	hFunc.Write(msg)
	hashOut := hFunc.Sum(nil)
	var sig, hashBig, hashSum, temp big.Int
	hashBig.SetBytes(hashOut)
	hashSum.Add(Min2048, &hashBig)
	sig.Exp(&hashSum, setup.D, setup.RSAMod)
	temp.Exp(&sig, setup.E, setup.RSAMod)
	// We are simplily checking the same message and signaure for many rounds
	if temp.Cmp(&hashSum) != 0 {
		fmt.Println("the RSA signature check fails in GenSigOffloadTestCircuit")
	}
	var acc, challenge, remainder, prod, deltamod big.Int
	prod.SetInt64(1)
	for i := 0; i < SetSize; i++ {
		prod.Mul(&prod, &hashSum)
	}
	// Additional parts for ZK
	ret.RanModL = make([]frontend.Variable, RanSetSize)
	ret.setSelect = make([]frontend.Variable, RanSetSize)
	retPub.RanModL = make([]frontend.Variable, RanSetSize)
	retPub.setSelect = make([]frontend.Variable, RanSetSize)
	ranSet := make([]big.Int, RanSetSize)
	for i := 0; i < RanSetSize; i++ {
		ranSet[i].Set(trustedSetup.H) // we set the random number with one value for test purpose!!
		//ranSet[i].Mod(&ranSet[i], &challenge)
		// ret.RanModL[i] = ranSet[i]
		// retPub.RanModL[i] = ranSet[i]
	}
	var copyX big.Int
	copyX.Set(&ranSet[0])
	for i := 0; i < RanSetSize; i++ {
		if copyX.Bit(0) == 1 {
			ret.setSelect[i] = 1
			prod.Mul(&prod, &ranSet[i])
		} else {
			ret.setSelect[i] = 0
		}
		copyX.Rsh(&copyX, 1)
	}
	//	Additional parts for ZK

	acc.Exp(trustedSetup.G, &prod, trustedSetup.N)
	// We should generate a commitment of x here and input into as part of the transcript. However, this version of gnark does not support CP-SNARK.
	transcript := fiatshamir.InitTranscript([]string{setup.Base.String(), setup.RSAMod.String(), trustedSetup.G.String(), trustedSetup.N.String(), acc.String()}, fiatshamir.Max252)
	challenge.Set(transcript.GetPrimeChallengeUsingTranscript())
	remainder.Mod(&prod, &challenge)
	deltamod.Mod(Min2048, &challenge)

	ret.ChallengeL = challenge
	retPub.ChallengeL = challenge
	ret.RemainderR = remainder
	retPub.RemainderR = remainder
	ret.DeltaModL = deltamod
	retPub.DeltaModL = deltamod
	ret.Messages = make([]frontend.Variable, SetSize)
	ret.HashOutputs = make([]frontend.Variable, SetSize)
	retPub.Messages = make([]frontend.Variable, SetSize)
	retPub.HashOutputs = make([]frontend.Variable, SetSize)
	for i := 0; i < SetSize; i++ {
		ret.Messages[i] = msg
		ret.HashOutputs[i] = hashBig
	}

	// Additional parts for ZK
	for i := 0; i < RanSetSize; i++ {
		ranSet[i].Mod(&ranSet[i], &challenge)
		ret.RanModL[i] = ranSet[i]
		retPub.RanModL[i] = ranSet[i]
	}
	//	Additional parts for ZK

	return &ret, &retPub
}

func TestOffloadZKSig() {
	if !isOffloadZKSigCircuitExist() {
		fmt.Println("Circuit haven't been compiled for RSAExpOffload. Start compiling.")
		startingTime := time.Now().UTC()
		SetupOffloadZKSig()
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Generating a SNARK circuit for RSAExpOffload, takes [%.3f] Seconds \n", duration.Seconds())
	} else {
		fmt.Println("Circuit have already been compiled for test purpose.")
	}
	fullcircuit, publiccircuit := GenZKSigOffloadTestCircuit(protocol.RSAExpSetup(), protocol.TrustedSetup())
	runtime.GC()
	fmt.Println("Start Proving")
	fileName := OffloadZKSigPrefix + "_original"
	startingTime := time.Now().UTC()
	pk, err := groth16.ReadSegmentProveKey(fileName)
	if err != nil {
		fmt.Println("error while ReadSegmentProveKey")
		return
	}
	r1cs, err := groth16.LoadR1CSFromFile(fileName)
	if err != nil {
		fmt.Println("error while LoadR1CSFromFile")
		return
	}
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Loading a SNARK circuit and proving key for OffloadingSignatures, takes [%.3f] Seconds \n", duration.Seconds())

	witness, err := frontend.NewWitness(fullcircuit, ecc.BN254)
	if err != nil {
		fmt.Println("error while AssignCircuit")
		return
	}
	runtime.GC()
	startingTime = time.Now().UTC()
	proof, err := groth16.ProveRoll(r1cs, pk[0], pk[1], witness, fileName, backend.IgnoreSolverError()) // backend.IgnoreSolverError() can be used for testing
	if err != nil {
		fmt.Println("error while ProveRoll")
		return
	}
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generating a SNARK proof for RSA exponentiation Offloading, takes [%.3f] Seconds \n", duration.Seconds())
	startingTime = time.Now().UTC()
	proof, err = groth16.ProveRoll(r1cs, pk[0], pk[1], witness, fileName, backend.IgnoreSolverError()) // backend.IgnoreSolverError() can be used for testing
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generating a SNARK proof for RSA exponentiation Offloading, takes [%.3f] Seconds \n", duration.Seconds())
	startingTime = time.Now().UTC()
	proof, err = groth16.ProveRoll(r1cs, pk[0], pk[1], witness, fileName, backend.IgnoreSolverError()) // backend.IgnoreSolverError() can be used for testing
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generating a SNARK proof for RSA exponentiation Offloading, takes [%.3f] Seconds \n", duration.Seconds())
	startingTime = time.Now().UTC()
	proof, err = groth16.ProveRoll(r1cs, pk[0], pk[1], witness, fileName, backend.IgnoreSolverError()) // backend.IgnoreSolverError() can be used for testing
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generating a SNARK proof for RSA exponentiation Offloading, takes [%.3f] Seconds \n", duration.Seconds())
	startingTime = time.Now().UTC()
	proof, err = groth16.ProveRoll(r1cs, pk[0], pk[1], witness, fileName, backend.IgnoreSolverError()) // backend.IgnoreSolverError() can be used for testing
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generating a SNARK proof for RSA exponentiation Offloading, takes [%.3f] Seconds \n", duration.Seconds())
	runtime.GC()
	vk, err := LoadVerifyingKey(fileName)
	if err != nil {
		panic("r1cs init error")
	}
	runtime.GC()
	publicWitness, err := frontend.NewWitness(publiccircuit, ecc.BN254, frontend.PublicOnly())
	if err != nil {
		fmt.Println("Error generating NewWitness in GenPublicWitness")
		return
	}
	startingTime = time.Now().UTC()
	err = groth16.Verify(proof, vk, publicWitness)
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Verifying a SNARK proof for RSAExpOffload, takes [%.3f] Seconds \n", duration.Seconds())
	if err != nil {
		fmt.Println("verify error = ", err)
		return
	}
	return
}
