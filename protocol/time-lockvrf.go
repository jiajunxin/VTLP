package protocol

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// GenVRF generates a verifiable random function value using rsasetup. Note that the rsasetup and in GenPuzzle can be different in practice
func GenVRF(message []byte, rsasetup *RSAExpProof) *big.Int {
	var element fr.Element
	element.SetBytes(message)
	return DIHashPoseidon(&element)
}

// GenPuzzle generates a time-lock puzzle using the parameters of RSAExpProof, s is the solution
func GenPuzzle(s *big.Int, rsasetup *RSAExpProof) *big.Int {
	var ret big.Int
	ret.Exp(s, rsasetup.Exponent, rsasetup.RSAMod)
	return &ret
}

// SolvePuzzle solves a time-lcok puuzle with Time parameter with respect to public key N
// This function takes a long time to solve!
func SolvePuzzle(z, N *big.Int) *big.Int {
	var ret, exp, temp big.Int
	temp.SetInt64(TimePara)
	exp.Exp(big2, &temp, N)
	ret.Exp(z, &exp, N)
	return &ret
}

// VTLPVRFProof contains the proofs for proving a time-lock puzzle
type VTLPVRFProof struct {
	pi1 *ZKPoMoDEFastProof
}

func PuzzleProve(pp *PublicParameters, message []byte, s *big.Int, rsasetup *RSAExpProof) (*VTLPVRFProof, error) {
	var ret VTLPVRFProof

	var C1, s2e, C2 big.Int
	// C = g^s, s^e mod N = Hash(m)
	C1.Exp(pp.G, s, pp.N)
	s2e.Exp(s, rsasetup.E, rsasetup.RSAMod)
	if s2e.Cmp(GenVRF(message, rsasetup)) != 0 {
		return nil, errors.New("PuzzleProve inputs an invalid statement")
	}
	C2.Exp(pp.G, &s2e, pp.N)
	tempProof1, err := ZKPoMoDEFastProve(pp, &C1, &C2, rsasetup.RSAMod, rsasetup.E, &s2e, s)
	if err != nil {
		return nil, err
	}
	ret.pi1 = tempProof1

	return &ret, nil
}
