package protocol

import (
	"crypto/sha256"
	"math/big"

	"github.com/consensys/gnark-crypto/hash"
)

// HashToPrime takes the input into Sha256 and take the hash output to input repeatedly until we hit a prime number
func HashToPrime(input []byte) *big.Int {
	var ret big.Int
	h := sha256.New()
	_, err := h.Write(input)
	if err != nil {
		panic(err)
	}
	hashTemp := h.Sum(nil)
	ret.SetBytes(hashTemp)
	flag := false
	for !flag {
		flag = ret.ProbablyPrime(securityParaHashToPrime)
		if !flag {
			h.Reset()
			_, err := h.Write(hashTemp)
			if err != nil {
				panic(err)
			}
			hashTemp = h.Sum(nil)
			ret.SetBytes(hashTemp)
		}
	}
	return &ret
}

// SHA256ToInt calculates the input with Sha256 and change it to big.Int
func SHA256ToInt(input []byte) *big.Int {
	var ret big.Int
	h := sha256.New()
	_, err := h.Write(input)
	if err != nil {
		panic(err)
	}
	hashTemp := h.Sum(nil)
	ret.SetBytes(hashTemp)
	return &ret
}

// SHA256ToInt calculates the input with Sha256 and change it to big.Int
func MiMcToInt(input []byte) *big.Int {
	hFunc := hash.MIMC_BN254.New()
	hFunc.Reset()

	if _, err := hFunc.Write(input); err != nil {
		return nil
	}
	var hramInt big.Int
	hramBin := hFunc.Sum(nil)
	hramInt.SetBytes(hramBin)
	return &hramInt
}

// MiMCWith2Inputs inputs 2 big.Int and generate a MiMC hash result.
func MiMCWith2Inputs(inputs []*big.Int) *big.Int {
	if len(inputs) != 2 {
		panic("MiMCWith2Inputs requires 2 inputs")
	}
	hFunc := hash.MIMC_BN254.New()
	hFunc.Reset()
	for _, bytes := range inputs {
		if _, err := hFunc.Write(bytes.Bytes()); err != nil {
			return nil
		}
	}
	var hramInt big.Int
	hramBin := hFunc.Sum(nil)
	hramInt.SetBytes(hramBin)
	return &hramInt
}
