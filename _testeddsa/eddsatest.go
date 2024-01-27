package main

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKey []PublicKey         `gnark:",public"`
	Signature []Signature         `gnark:",public"`
	Message   []frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {

	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	for i := 0; i < size; i++ {
		err = Verify(curve, circuit.Signature[i], circuit.Message[i], circuit.PublicKey[i], &mimc)
		mimc.Reset()
	}
	return err
}

type MiMcCircuit struct {
	curveID     tedwards.ID
	Message     []frontend.Variable `gnark:",public"`
	HashOutputs []frontend.Variable `gnark:",public"`
}

func (circuit *MiMcCircuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	var temp frontend.Variable
	// verify the signature in the cs
	for i := 0; i < size; i++ {
		mimc.Write(circuit.Message[i])
		temp = mimc.Sum()
		api.AssertIsEqual(temp, circuit.HashOutputs[i])
		mimc.Reset()
	}
	return err
}
