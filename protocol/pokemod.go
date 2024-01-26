package protocol

import (
	"crypto/rand"
	"errors"
	"math/big"

	fiatshamir "github.com/PoMoDE/fiat-shamir"
)

// ZKPoKEModProof contains the proofs for ZKPoKEMod
type ZKPoKEModProof struct {
	D  *big.Int
	pi *PoKEStarProof
	Q  *big.Int
	r  *big.Int
}

func ZKPoKEModProve(pp *PublicParameters, C, x, n, xmod *big.Int) (*ZKPoKEModProof, error) {
	// input checks
	var temp big.Int
	temp.Mod(x, n)
	if temp.Cmp(xmod) != 0 {
		return nil, errors.New("ZKPoKEModN inputs a invalid statement")
	}
	temp.Exp(pp.G, x, pp.N)
	if temp.Cmp(C) != 0 {
		return nil, errors.New("ZKPoKEModN inputs a invalid statement")
	}

	var ret ZKPoKEModProof

	b := new(big.Int).Set(pp.N)
	lsh := 2*securityPara - 2
	b.Lsh(b, uint(lsh))
	m, err := rand.Int(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	ret.D = new(big.Int).Exp(pp.G, m, pp.N)
	proof, err := PoKEStarProve(pp, ret.D, m)
	if err != nil {
		return nil, err
	}
	ret.pi = proof

	var l big.Int
	transcript := fiatshamir.InitTranscript([]string{"ZKPoKEMod", pp.G.String(), pp.N.String(),
		C.String(), n.String(), xmod.String(), ret.pi.Q.String(), ret.pi.R.String()}, fiatshamir.Max252)
	l.Set(transcript.GetPrimeChallengeUsingTranscript())

	var exp, q, r big.Int //exp = x + mn
	exp.Mul(m, n)
	exp.Add(&exp, x)
	temp.Mul(&l, n) //temp = l*n
	q.DivMod(&exp, &temp, &r)
	ret.Q = new(big.Int).Exp(pp.G, &q, pp.N)
	ret.r = new(big.Int).Set(&r)
	return &ret, nil
}

func ZKPoKEModVerify(pp *PublicParameters, C, n, xmod *big.Int, proof *ZKPoKEModProof) bool {
	if proof == nil || proof.pi == nil {
		return false
	}
	flag := PoKEStarVerify(pp, proof.D, proof.pi)
	if flag != true {
		return false
	}
	var l big.Int
	transcript := fiatshamir.InitTranscript([]string{"ZKPoKEMod", pp.G.String(), pp.N.String(),
		C.String(), n.String(), xmod.String(), proof.pi.Q.String(), proof.pi.R.String()}, fiatshamir.Max252)
	l.Set(transcript.GetPrimeChallengeUsingTranscript())

	var temp, lhs, rhs big.Int
	temp.Mul(&l, n) //temp = l*n
	if temp.Cmp(proof.r) != 1 {
		return false
	}
	lhs.Set(MultiExp(proof.Q, &temp, pp.G, proof.r, pp.N))
	rhs.Exp(proof.D, n, pp.N)
	rhs.Mul(&rhs, C)
	rhs.Mod(&rhs, pp.N)
	if lhs.Cmp(&rhs) != 0 {
		return false
	}
	temp.Mod(proof.r, n)
	if temp.Cmp(xmod) != 0 {
		return false
	}
	return true
}
