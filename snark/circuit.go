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
	squares    []frontend.Variable // list of user balances before update
	ChallengeL frontend.Variable   `gnark:",public"` // a prime challenge number L
	RemainderR frontend.Variable   `gnark:",public"` // a remainder R
	//------------------------------private witness below--------------------------------------
	x []frontend.Variable // the exponent x. The original bit length of x is 2048, we pack it using 9 variable
}

// Define declares the circuit constraints
func (circuit VLTPCircuit) Define(api frontend.API) error {
	//check input are in the correct range
	api.AssertIsLess(circuit.RemainderR, circuit.ChallengeL)
	api.AssertIsEqual(len(circuit.squares), BitLength)
	api.AssertIsEqual(len(circuit.x), LimbNum)
	// ToBinary not only returns the binary, but additionaly checks if the binary representation is same as the input,
	var remainderTemp, one frontend.Variable = 1, 1
	for i := 0; i < LimbNum; i++ {
		binaryArray := api.ToBinary(circuit.x[i], LimbSize)
		for j := 0; j < LimbSize; j++ {
			temp := api.Select(binaryArray[j], circuit.squares[i*LimbNum+j], one)
			api.MulModP(temp, remainderTemp, circuit.ChallengeL)
		}
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

	circuit.squares = make([]frontend.Variable, BitLength)
	circuit.x = make([]frontend.Variable, LimbNum)
	for i := 0; i < BitLength; i++ {
		circuit.squares[i] = i
	}
	for i := 0; i < LimbNum; i++ {
		circuit.x[i] = 0
	}

	return &circuit
}

// Get the lowest LimbSize bits of the inputs
func getLowerBits(input *big.Int) *big.Int {
	var ret, modular, big2, limbNum big.Int
	big2.SetInt64(int64(2))
	limbNum.SetInt64(int64(LimbNum))
	modular.Exp(&big2, &limbNum, nil)
	ret.Mod(input, &modular)
	return &ret
}

// AssignCircuit assign a circuit with ExpCircuitInputs values.
func AssignCircuit(input *ExpCircuitInputs) *VLTPCircuit {
	var circuit VLTPCircuit
	circuit.ChallengeL = input.ChallengeL
	circuit.RemainderR = input.RemainderR
	circuit.squares = make([]frontend.Variable, BitLength)
	circuit.x = make([]frontend.Variable, LimbNum)
	for i := 0; i < BitLength; i++ {
		circuit.squares[i] = input.Squares[i]
	}

	var expCopy big.Int
	expCopy.Set(&input.Exponent)
	for i := 0; i < LimbNum; i++ {
		circuit.x[i] = getLowerBits(&expCopy)
		expCopy.Rsh(&expCopy, LimbNum)
	}
	return &circuit
}

// AssignCircuitHelper assign a circuit with PublicInfo values.
func AssignCircuitHelper(input *ExpCircuitPublicInputs) *VLTPCircuit {
	var circuit VLTPCircuit
	circuit.ChallengeL = input.ChallengeL
	circuit.RemainderR = input.RemainderR
	circuit.squares = make([]frontend.Variable, BitLength)
	circuit.x = make([]frontend.Variable, LimbNum)
	for i := 0; i < BitLength; i++ {
		circuit.squares[i] = input.Squares[i]
	}

	return &circuit
}
