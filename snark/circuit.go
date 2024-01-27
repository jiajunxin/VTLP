package snark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// VLTPCircuit is the Verifiable Time-lock puzzle for NP circuit for gnark.
// gnark is a zk-SNARK library written in Go. Circuits are regular structs.
// The inputs must be of type frontend.Variable and make up the witness.
type VLTPCircuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	SquaresMod []frontend.Variable `gnark:",public"` // a prime challenge number L
	ChallengeL frontend.Variable   `gnark:",public"` // a prime challenge number L
	RemainderR frontend.Variable   `gnark:",public"` // a remainder R
	//------------------------------private witness below--------------------------------------
	x []frontend.Variable // the exponent x.
}

// Define declares the circuit constraints
func (circuit VLTPCircuit) Define(api frontend.API) error {
	//check input are in the correct range
	api.AssertIsLess(circuit.RemainderR, circuit.ChallengeL)
	api.AssertIsEqual(len(circuit.SquaresMod), BitLength)
	api.AssertIsEqual(len(circuit.x), BitLength)
	// ToBinary not only returns the binary, but additionaly checks if the binary representation is same as the input,
	var remainderTemp frontend.Variable = 1
	for i := 0; i < BitLength; i++ {
		temp := api.MulModP(remainderTemp, circuit.SquaresMod[i], circuit.ChallengeL)
		remainderTemp = api.Select(circuit.x[i], temp, remainderTemp)
	}

	// To be modified
	api.AssertIsLess(remainderTemp, circuit.RemainderR)
	return nil
}

// InitCircuit init a circuit with challenges, OriginalHashes and CurrentEpochNum value 1, all other values 0. Use for test purpose only.
func InitCircuit() *VLTPCircuit {
	var circuit VLTPCircuit
	circuit.ChallengeL = 1
	circuit.RemainderR = 0

	circuit.SquaresMod = make([]frontend.Variable, BitLength)
	circuit.x = make([]frontend.Variable, BitLength)
	for i := 0; i < BitLength; i++ {
		circuit.SquaresMod[i] = 1
	}
	for i := 0; i < BitLength; i++ {
		circuit.x[i] = 0
	}

	return &circuit
}

// AssignCircuit assign a circuit with ExpCircuitInputs values.
func AssignCircuit(input *ExpCircuitInputs) *VLTPCircuit {
	var circuit VLTPCircuit
	circuit.ChallengeL = input.ChallengeL
	circuit.RemainderR = input.RemainderR
	circuit.SquaresMod = make([]frontend.Variable, BitLength)
	circuit.x = make([]frontend.Variable, BitLength)
	for i := 0; i < BitLength; i++ {
		circuit.SquaresMod[i] = input.SquaresMod[i]
	}

	var copyX big.Int
	copyX.Set(&input.Exponent)
	for i := 0; i < BitLength; i++ {
		if copyX.Bit(0) == 1 {
			circuit.x[i] = 1
		} else {
			circuit.x[i] = 0
		}
		copyX.Rsh(&copyX, 1)
	}
	return &circuit
}

// AssignCircuitHelper assign a circuit with PublicInfo values.
func AssignCircuitHelper(input *ExpCircuitPublicInputs) *VLTPCircuit {
	var circuit VLTPCircuit
	circuit.ChallengeL = input.ChallengeL
	circuit.RemainderR = input.RemainderR
	circuit.SquaresMod = make([]frontend.Variable, BitLength)
	circuit.x = make([]frontend.Variable, BitLength)
	for i := 0; i < BitLength; i++ {
		circuit.SquaresMod[i] = input.SquaresMod[i]
	}

	return &circuit
}
