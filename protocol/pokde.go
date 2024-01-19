package protocol

import (
	"math/big"

	fiatshamir "github.com/PoMoDE/fiat-shamir"
)

// PoKDEProof contains the proofs for PoKDE
type PoKDEProof struct {
	Q1 *big.Int
	r1 *big.Int
	Q2 *big.Int
	r2 *big.Int
}

func PoKDEProve(pp *PublicParameters, C1, C2, e, x *big.Int) (*PoKDEProof, error) {
	var l, q1, q2, r1, r2 big.Int
	transcript := fiatshamir.InitTranscript([]string{"PoKDE", pp.G.String(), pp.N.String(), C1.String(), C1.String(), e.String()}, fiatshamir.Max252)
	l.Set(transcript.GetPrimeChallengeUsingTranscript())
	var ret PoKDEProof
	q1.DivMod(x, &l, &r1)
	q2.DivMod(x, &l, &r2)
	ret.Q1 = new(big.Int).Exp(pp.G, &q1, pp.N)
	ret.Q2 = new(big.Int).Exp(pp.G, &q2, pp.N)
	ret.r1 = new(big.Int).Set(&r1)
	ret.r2 = new(big.Int).Set(&r2)

	return &ret, nil
}

func PoKDEVerify(pp *PublicParameters, C1, C2, e *big.Int, proof *PoKDEProof) bool {
	if proof == nil || proof.Q1 == nil || proof.Q2 == nil || proof.r1 == nil || proof.r2 == nil {
		return false
	}
	var l, temp big.Int
	transcript := fiatshamir.InitTranscript([]string{"PoKDE", pp.G.String(), pp.N.String(), C1.String(), C1.String(), e.String()}, fiatshamir.Max252)
	l.Set(transcript.GetPrimeChallengeUsingTranscript())
	if proof.r1.Cmp(&l) != -1 || proof.r2.Cmp(&l) != -1 {
		return false
	}
	temp.Set(MultiExp(proof.Q1, &l, pp.G, proof.r1, pp.N))
	if temp.Cmp(C1) != 0 {
		return false
	}
	temp.Set(MultiExp(proof.Q2, &l, pp.G, proof.r2, pp.N))
	if temp.Cmp(C2) != 0 {
		return false
	}
	return true
}
