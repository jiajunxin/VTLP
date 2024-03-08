package main

import (
	crand "crypto/rand"
	"fmt"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

//"github.com/PoMoDE/snark"
//"github.com/PoMoDE/protocol"

const size = 1

// GetAssign generate a test assignment of circuit for Testing!
func GetAssign() *eddsaCircuit {
	hFunc := hash.MIMC_BN254.New()
	privateKey, err := eddsa.New(tedwards.BN254, crand.Reader)
	if err != nil {
		fmt.Println("err = ", err)
	}
	publicKey := privateKey.Public()
	msg := make([]byte, 32)
	msg[0] = 0x0d
	signature, err := privateKey.Sign(msg, hFunc)
	isValid, err := publicKey.Verify(signature, msg, hFunc)
	if !isValid {
		fmt.Println("1. invalid signature")
	} else {
		fmt.Println("1. valid signature")
	}
	var assignment eddsaCircuit
	// assign message value
	assignment.Message = make([]frontend.Variable, size)
	assignment.PublicKey = make([]PublicKey, size)
	assignment.Signature = make([]Signature, size)
	// public key bytes
	_publicKey := publicKey.Bytes()
	// assign public key values
	for i := 0; i < size; i++ {
		assignment.Message[i] = msg
		assignment.PublicKey[i].Assign(tedwards.BN254, _publicKey[:32])
		// assign signature values
		assignment.Signature[i].Assign(tedwards.BN254, signature)
	}
	return &assignment
}

func GetEmptyAssign() *eddsaCircuit {
	var assignment eddsaCircuit
	// assign message value
	assignment.Message = make([]frontend.Variable, size)
	assignment.PublicKey = make([]PublicKey, size)
	assignment.Signature = make([]Signature, size)
	assignment.curveID = tedwards.BN254
	return &assignment
}

// GetMiMcAssign generate a test assignment of circuit for Testing!
func GetMiMcAssign() *MiMcCircuit {
	hash := hash.MIMC_BN254.New()

	msg := make([]byte, 32)
	msg[0] = 0x0d
	hash.Write(msg)
	var assignment MiMcCircuit
	hashOut := hash.Sum(nil)
	// assign message value
	assignment.Message = make([]frontend.Variable, size)
	assignment.HashOutputs = make([]frontend.Variable, size)
	// assign public key values
	for i := 0; i < size; i++ {
		assignment.Message[i] = msg
		assignment.HashOutputs[i] = hashOut
	}
	return &assignment
}

func GetEmptyMiMcAssign() *MiMcCircuit {
	hash := hash.MIMC_BN254.New()

	msg := make([]byte, 32)
	msg[0] = 0x0d
	hash.Write(msg)
	var assignment MiMcCircuit
	hashOut := hash.Sum(nil)
	// assign message value
	assignment.Message = make([]frontend.Variable, size)
	assignment.HashOutputs = make([]frontend.Variable, size)
	// assign public key values
	for i := 0; i < size; i++ {
		assignment.Message[i] = msg
		assignment.HashOutputs[i] = hashOut
	}
	return &assignment
}

func main() {
	snarkField, _ := twistededwards.GetSnarkField(tedwards.BN254)

	fmt.Println("Testing ", size, " MiMc hash checks using Groth16")
	ccs, _ := frontend.Compile(snarkField, r1cs.NewBuilder, GetEmptyMiMcAssign())
	ccs.GetNbConstraints()
	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)
	witness, err := frontend.NewWitness(GetMiMcAssign(), snarkField)
	publicWitness, err := witness.Public()
	// generate the proof
	proof, err := groth16.Prove(ccs, pk, witness)
	proof, err = groth16.Prove(ccs, pk, witness)
	proof, err = groth16.Prove(ccs, pk, witness)
	proof, err = groth16.Prove(ccs, pk, witness)
	proof, err = groth16.Prove(ccs, pk, witness)
	// verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Error = ", err)
	}

	fmt.Println("Testing ", size, " MiMc hash&EdDSA checks using Groth16")
	//fmt.Println("snarkField = ", snarkField.String())
	ccs2, _ := frontend.Compile(snarkField, r1cs.NewBuilder, GetEmptyAssign())
	ccs2.GetNbConstraints()
	// groth16 zkSNARK: Setup
	pk2, vk2, _ := groth16.Setup(ccs2)
	witness2, err := frontend.NewWitness(GetAssign(), snarkField)
	if err != nil {
		fmt.Println("Error = ", err)
	}
	publicWitness2, err := witness2.Public()
	// generate the proof
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
