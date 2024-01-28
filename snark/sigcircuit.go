package snark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

const SetSize = 1000
const RanSetSize = 2048

type SigCircuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	//SquaresMod []frontend.Variable `gnark:",public"` //
	ChallengeL frontend.Variable `gnark:",public"` // a prime challenge number L
	RemainderR frontend.Variable `gnark:",public"` // a remainder R
	DeltaModL  frontend.Variable `gnark:",public"` // Delta is a large number with 2048 bits
	//------------------------------private witness below--------------------------------------
	Messages    []frontend.Variable
	HashOutputs []frontend.Variable
}

// Define declares the circuit constraints
func (circuit SigCircuit) Define(api frontend.API) error {
	//check input are in the correct range
	api.AssertIsLess(circuit.RemainderR, circuit.ChallengeL)
	api.AssertIsLess(circuit.DeltaModL, circuit.ChallengeL)
	api.AssertIsEqual(len(circuit.Messages), len(circuit.HashOutputs))
	// ToBinary not only returns the binary, but additionaly checks if the binary representation is same as the input,
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	var temp frontend.Variable
	mimc.Reset()
	// verify the hashes
	for i := 0; i < SetSize; i++ {
		mimc.Write(circuit.Messages[i])
		temp = mimc.Sum()
		api.AssertIsEqual(temp, circuit.HashOutputs[i])
		mimc.Reset()
	}
	// verify the remainder
	var remainderTemp frontend.Variable = 1
	for i := 0; i < SetSize; i++ {
		temp2 := api.AddModP(circuit.HashOutputs[i], circuit.DeltaModL, circuit.ChallengeL)
		remainderTemp = api.MulModP(temp2, remainderTemp, circuit.ChallengeL)
	}

	// To be modified
	api.AssertIsLess(remainderTemp, circuit.ChallengeL)
	return nil
}

// InitCircuit init a circuit with challenges, OriginalHashes and CurrentEpochNum value 1, all other values 0. Use for test purpose only.
func InitCircuitSig() *SigCircuit {
	var circuit SigCircuit
	circuit.ChallengeL = 1
	circuit.RemainderR = 0
	circuit.DeltaModL = 1

	circuit.Messages = make([]frontend.Variable, SetSize)
	circuit.HashOutputs = make([]frontend.Variable, SetSize)
	for i := 0; i < SetSize; i++ {
		circuit.Messages[i] = 1
		circuit.HashOutputs[i] = 1
	}
	return &circuit
}

type ZKSigCircuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	//SquaresMod []frontend.Variable `gnark:",public"` //
	ChallengeL frontend.Variable   `gnark:",public"` // a prime challenge number L
	RemainderR frontend.Variable   `gnark:",public"` // a remainder R
	DeltaModL  frontend.Variable   `gnark:",public"` // Delta is a large number with 2048 bits
	RanModL    []frontend.Variable `gnark:",public"`
	//------------------------------private witness below--------------------------------------
	Messages    []frontend.Variable
	HashOutputs []frontend.Variable
	setSelect   []frontend.Variable
}

// Define declares the circuit constraints
func (circuit ZKSigCircuit) Define(api frontend.API) error {
	//check input are in the correct range
	api.AssertIsLess(circuit.RemainderR, circuit.ChallengeL)
	api.AssertIsLess(circuit.DeltaModL, circuit.ChallengeL)
	api.AssertIsEqual(len(circuit.Messages), len(circuit.HashOutputs))
	api.AssertIsEqual(len(circuit.RanModL), len(circuit.setSelect))
	// ToBinary not only returns the binary, but additionaly checks if the binary representation is same as the input,
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	var temp frontend.Variable
	mimc.Reset()
	// verify the hashes
	for i := 0; i < SetSize; i++ {
		mimc.Write(circuit.Messages[i])
		temp = mimc.Sum()
		api.AssertIsEqual(temp, circuit.HashOutputs[i])
		mimc.Reset()
	}
	// verify the remainder
	var remainderTemp frontend.Variable = 1
	for i := 0; i < SetSize; i++ {
		temp2 := api.AddModP(circuit.HashOutputs[i], circuit.DeltaModL, circuit.ChallengeL)
		remainderTemp = api.MulModP(temp2, remainderTemp, circuit.ChallengeL)
	}
	for i := 0; i < RanSetSize; i++ {
		temp := api.MulModP(remainderTemp, circuit.RanModL[i], circuit.ChallengeL)
		remainderTemp = api.Select(circuit.setSelect[i], temp, remainderTemp)
	}

	// To be modified
	api.AssertIsLess(remainderTemp, circuit.ChallengeL)
	return nil
}

// InitCircuit init a circuit with challenges, OriginalHashes and CurrentEpochNum value 1, all other values 0. Use for test purpose only.
func InitCircuitZKSig() *ZKSigCircuit {
	var circuit ZKSigCircuit
	circuit.ChallengeL = 1
	circuit.RemainderR = 0
	circuit.DeltaModL = 1

	circuit.Messages = make([]frontend.Variable, SetSize)
	circuit.HashOutputs = make([]frontend.Variable, SetSize)
	circuit.RanModL = make([]frontend.Variable, RanSetSize)
	circuit.setSelect = make([]frontend.Variable, RanSetSize)
	for i := 0; i < SetSize; i++ {
		circuit.Messages[i] = 1
		circuit.HashOutputs[i] = 1
	}
	for i := 0; i < RanSetSize; i++ {
		circuit.RanModL[i] = 1
		circuit.setSelect[i] = 1
	}
	return &circuit
}
