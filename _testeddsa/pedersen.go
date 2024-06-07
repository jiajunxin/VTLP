package main

import (
	"fmt"
	"runtime"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type PedersenCircuit struct {
	curveID    tedwards.ID
	commitment twistededwards.Point `gnark:",public"`
	preimage   []frontend.Variable
}

func (circuit *PedersenCircuit) Define(api frontend.API) error {

	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	baseG := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}
	baseH := curve.Neg(baseG) // we use the same base for benchmark
	Q := curve.DoubleBaseScalarMul(baseG, baseH, circuit.preimage[0], circuit.preimage[1])
	curve.AssertIsOnCurve(Q)
	Q = curve.Add(curve.Neg(Q), circuit.commitment)
	// Should be AssertIsEqual, we use AssertIsDifferent for simplicity of test
	curve.API().AssertIsDifferent(Q.X, 0)
	curve.API().AssertIsDifferent(Q.Y, 1)
	return err
}

// GetAssign generate a test assignment of circuit for Testing!
func GetPedersenAssign() *PedersenCircuit {
	var assignment PedersenCircuit
	// assign message value
	assignment.preimage = make([]frontend.Variable, 2)
	assignment.curveID = tedwards.BN254
	assignment.preimage[0] = 1
	assignment.preimage[1] = 1
	assignment.commitment = *new(twistededwards.Point)
	assignment.commitment.X = 1
	assignment.commitment.Y = 1
	return &assignment
}

func GetEmptyPedersenAssign() *PedersenCircuit {
	var assignment PedersenCircuit
	// assign message value
	assignment.curveID = tedwards.BN254
	assignment.preimage = make([]frontend.Variable, 2)
	assignment.preimage[0] = 1
	assignment.preimage[1] = 1
	assignment.commitment = *new(twistededwards.Point)

	return &assignment
}

func testPedersenCircuit() {
	snarkField, _ := twistededwards.GetSnarkField(tedwards.BN254)
	fmt.Println("Testing PedersenCircuit using Groth16")
	//fmt.Println("snarkField = ", snarkField.String())
	ccs2, _ := frontend.Compile(snarkField, r1cs.NewBuilder, GetEmptyPedersenAssign())
	ccs2.GetNbConstraints()
	// groth16 zkSNARK: Setup
	pk2, vk2, _ := groth16.Setup(ccs2)
	witness2, err := frontend.NewWitness(GetPedersenAssign(), snarkField)
	if err != nil {
		fmt.Println("Error = ", err)
	}
	publicWitness2, err := witness2.Public()
	if err != nil {
		fmt.Println("Error = ", err)
	}
	// generate the proof
	runtime.GC()
	proof2, err := groth16.Prove(ccs2, pk2, witness2)
	proof2, err = groth16.Prove(ccs2, pk2, witness2)
	proof2, err = groth16.Prove(ccs2, pk2, witness2)
	proof2, err = groth16.Prove(ccs2, pk2, witness2)
	proof2, err = groth16.Prove(ccs2, pk2, witness2)

	// verify the proof
	err = groth16.Verify(proof2, vk2, publicWitness2)
	if err != nil {
		fmt.Println("Error = ", err)
	}
}
