package snark

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"time"

	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	fiatshamir "github.com/PoMoDE/fiat-shamir"
	"github.com/PoMoDE/protocol"
)

const (
	// BitLength is the bit length of the RSA modular N, BitLength should be less than LimbSize * LimbNum
	BitLength = 1024

	// KeyPathPrefix denotes the path to store the circuit and keys. fileName = KeyPathPrefix + "_" + _original
	KeyPathPrefix      = "RSAExpOffload"
	OffloadSigPrefix   = "OffloadSig"
	OffloadZKSigPrefix = "OffloadZKSig"
)

// ExpCircuitInputs is the inputs for the circuit VLTPCircuit
type ExpCircuitInputs struct {
	ChallengeL big.Int
	RemainderR big.Int
	SquaresMod []big.Int
	Exponent   big.Int
}

// ExpCircuitPublicInputs is the public information part of ExpCircuitInputs
type ExpCircuitPublicInputs struct {
	ChallengeL big.Int
	RemainderR big.Int
	SquaresMod []big.Int
}

func GetSquares(base, mod *big.Int) []big.Int {
	big2 := new(big.Int).SetInt64(2)
	ret := make([]big.Int, BitLength)
	ret[0].Set(base)
	for i := 1; i < BitLength; i++ {
		ret[i].Exp(&ret[i-1], big2, mod)
	}
	return ret
}

func GetProd(base, exp, mod *big.Int) *big.Int {
	var prod big.Int
	big2 := new(big.Int).SetInt64(2)
	squares := make([]big.Int, mod.BitLen())
	squares[0].Set(base)
	for i := 1; i < mod.BitLen(); i++ {
		squares[i].Exp(&squares[i-1], big2, mod)
	}

	bitLen := exp.BitLen()
	prod.SetInt64(1)
	for i := 0; i < bitLen; i++ {
		if exp.Bit(i) == 1 {
			prod.Mul(&prod, &squares[i])
		}
	}
	return &prod
}

// GenTestSet generates a set of values for test purpose.
func GenVLTPTestSet(exponent *big.Int, setup *protocol.Setup) *ExpCircuitInputs {
	var ret ExpCircuitInputs
	rsaExp := protocol.RSAExpSetup()
	tempSlice := GetSquares(rsaExp.Base, rsaExp.RSAMod)
	if exponent == nil {
		ret.Exponent.Set(rsaExp.Exponent) //set it to a random number for test
	}
	prod := GetProd(rsaExp.Base, rsaExp.Exponent, rsaExp.RSAMod)
	var acc, remainder big.Int
	acc.Exp(setup.G, prod, setup.N)
	// We should generate a commitment of x here and input into as part of the transcript. However, this version of gnark does not support CP-SNARK.
	transcript := fiatshamir.InitTranscript([]string{rsaExp.Base.String(), rsaExp.RSAMod.String(), setup.G.String(), setup.N.String(), acc.String()}, fiatshamir.Max252)
	ret.ChallengeL.Set(transcript.GetPrimeChallengeUsingTranscript())
	ret.SquaresMod = make([]big.Int, BitLength)
	for i := 0; i < BitLength; i++ {
		ret.SquaresMod[i].Mod(&tempSlice[i], &ret.ChallengeL)
	}
	remainder.Mod(prod, &ret.ChallengeL)
	ret.RemainderR.Set(&remainder)
	return &ret
}

// PublicPart returns a new UpdateSet32 with same public part and hidden part 0
func (input *ExpCircuitInputs) PublicPart() *ExpCircuitPublicInputs {
	var ret ExpCircuitPublicInputs
	ret.ChallengeL = input.ChallengeL
	ret.RemainderR = input.RemainderR
	ret.SquaresMod = make([]big.Int, BitLength)
	for i := 0; i < BitLength; i++ {
		ret.SquaresMod = input.SquaresMod
	}
	return &ret
}

func isCircuitExist() bool {
	fileName := KeyPathPrefix + "_original.vk.save"
	_, err := os.Stat(fileName)
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}

// TestRSAOffload is temporarily used for test purpose
func TestRSAOffload() {
	if !isCircuitExist() {
		fmt.Println("Circuit haven't been compiled for RSAExpOffload. Start compiling.")
		startingTime := time.Now().UTC()
		SetupVTLP()
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Generating a SNARK circuit for RSAExpOffload, takes [%.3f] Seconds \n", duration.Seconds())
	} else {
		fmt.Println("Circuit have already been compiled for test purpose.")
	}
	testSet := GenVLTPTestSet(nil, protocol.TrustedSetup())
	publicInfo := testSet.PublicPart()
	runtime.GC()
	proof, err := Prove(testSet)
	if err != nil {
		fmt.Println("Error during Prove")
		panic(err)
	}
	runtime.GC()
	flag := Verify(proof, publicInfo)
	if flag {
		fmt.Println("Verification passed")
		return
	}
	fmt.Println("Verification failed")
}

// LoadVerifyingKey load the verification key from the filepath
func LoadVerifyingKey(filepath string) (verifyingKey groth16.VerifyingKey, err error) {
	verifyingKey = groth16.NewVerifyingKey(ecc.BN254)
	f, _ := os.Open(filepath + ".vk.save")
	_, err = verifyingKey.ReadFrom(f)
	if err != nil {
		return verifyingKey, fmt.Errorf("read file error")
	}
	err = f.Close()
	if err != nil {
		return verifyingKey, fmt.Errorf("close file error")
	}
	return verifyingKey, nil
}

// SetupVTLP generates the circuit and public/verification keys with Groth16
func SetupVTLP() {
	// compiles our circuit into a R1CS
	circuit := InitCircuit()
	fmt.Println("Start Compiling")
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, circuit) //, frontend.IgnoreUnconstrainedInputs()
	if err != nil {
		panic(err)
	}
	fmt.Println("Finish Compiling")
	fmt.Println("Number of constrains: ", r1cs.GetNbConstraints())

	fileName := KeyPathPrefix + "_original"
	err = groth16.SetupLazyWithDump(r1cs, fileName)
	if err != nil {
		panic(err)
	}
	fmt.Println("Finish Setup")
}

// Prove is used to generate a Groth16 proof and public witness for the VTLP
func Prove(input *ExpCircuitInputs) (*groth16.Proof, error) {
	fmt.Println("Start Proving")
	fileName := KeyPathPrefix + "_original"
	startingTime := time.Now().UTC()
	pk, err := groth16.ReadSegmentProveKey(fileName)
	if err != nil {
		fmt.Println("error while ReadSegmentProveKey")
		return nil, err
	}
	r1cs, err := groth16.LoadR1CSFromFile(fileName)
	if err != nil {
		fmt.Println("error while LoadR1CSFromFile")
		return nil, err
	}
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Loading a SNARK circuit and proving key for RSA exponentiation Offloading, takes [%.3f] Seconds \n", duration.Seconds())

	assignment := AssignCircuit(input)
	witness, err := frontend.NewWitness(assignment, ecc.BN254)
	if err != nil {
		fmt.Println("error while AssignCircuit")
		return nil, err
	}
	runtime.GC()
	startingTime = time.Now().UTC()
	proof, err := groth16.ProveRoll(r1cs, pk[0], pk[1], witness, fileName, backend.IgnoreSolverError()) // backend.IgnoreSolverError() can be used for testing
	if err != nil {
		fmt.Println("error while ProveRoll")
		return nil, err
	}
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generating a SNARK proof for RSA exponentiation Offloading, takes [%.3f] Seconds \n", duration.Seconds())
	return &proof, nil
}

// VerifyPublicWitness returns true is the public witness
func VerifyPublicWitness(publicWitness *witness.Witness, publicInfo *ExpCircuitPublicInputs) bool {
	startingTime := time.Now().UTC()
	assignment2 := AssignCircuitHelper(publicInfo)
	publicWitness2, err := frontend.NewWitness(assignment2, ecc.BN254, frontend.PublicOnly())
	if err != nil {
		fmt.Println("Error generating NewWitness")
		return false
	}
	if !reflect.DeepEqual(publicWitness.Vector, publicWitness2.Vector) {
		fmt.Println("Verification failed for publicWitness")
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Checking publicWitness using reflect takes [%.3f] Seconds \n", duration.Seconds())
		return false
	}
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Checking publicWitness using reflect takes [%.3f] Seconds \n", duration.Seconds())
	return true
}

// GenPublicWitness generates the publicWitness based on publicInfo
func GenPublicWitness(publicInfo *ExpCircuitPublicInputs) *witness.Witness {
	assignment := AssignCircuitHelper(publicInfo)
	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254, frontend.PublicOnly())
	if err != nil {
		fmt.Println("Error generating NewWitness in GenPublicWitness")
		return nil
	}
	return publicWitness
}

// Verify is used to check a Groth16 proof and public inputs
func Verify(proof *groth16.Proof, publicInfo *ExpCircuitPublicInputs) bool {
	fileName := KeyPathPrefix + "_original"
	vk, err := LoadVerifyingKey(fileName)
	if err != nil {
		panic("r1cs init error")
	}
	runtime.GC()
	startingTime := time.Now().UTC()
	publicWitness := GenPublicWitness(publicInfo)
	if publicWitness == nil {
		return false
	}
	err = groth16.Verify(*proof, vk, publicWitness)
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Verifying a SNARK proof for RSAExpOffload, takes [%.3f] Seconds \n", duration.Seconds())
	if err != nil {
		fmt.Println("verify error = ", err)
		return false
	}
	return true
}
