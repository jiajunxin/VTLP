package protocol

import (
	"crypto/rand"
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

// PoKDEProve prove C1=g^x, C2=g^{x^e}
func PoKDEProve(pp *PublicParameters, C1, C2, x, e *big.Int) (*PoKDEProof, error) {
	var xe, l, q1, q2, r1, r2 big.Int
	xe.Exp(x, e, nil)
	transcript := fiatshamir.InitTranscript([]string{"PoKDE", pp.G.String(), pp.N.String(), C1.String(), C1.String(), e.String()}, fiatshamir.Max252)
	l.Set(transcript.GetPrimeChallengeUsingTranscript())
	var ret PoKDEProof
	q1.DivMod(x, &l, &r1)
	q2.DivMod(&xe, &l, &r2)
	ret.Q1 = new(big.Int).Exp(pp.G, &q1, pp.N)
	ret.Q2 = new(big.Int).Exp(pp.G, &q2, pp.N)
	ret.r1 = new(big.Int).Set(&r1)
	ret.r2 = new(big.Int).Set(&r2)

	return &ret, nil
}

// PoKDEVerify checks the proof, returns true if everything is good
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

// ZKPoKDEProof contains the proofs for PoKDE
type ZKPoKDEProof struct {
	pi1 *PoKEStarProof
	D   *big.Int
	E   *big.Int
	F   *big.Int
	K   *big.Int
	pi2 *PoEProof
	pi3 *ZKPoKEProof
	pi4 *PoKDEProof
}

// ZKPoKDEProve prove C1=g^x, C2=g^{x^e} in zero-knowledge
func ZKPoKDEProve(pp *PublicParameters, C1, C2, x, e *big.Int) (*ZKPoKDEProof, error) {
	var ret ZKPoKDEProof

	length := 2048 + 256
	var b big.Int
	b.SetInt64(1)
	b.Lsh(&b, uint(length))
	m, err := rand.Int(rand.Reader, &b)
	if err != nil {
		return nil, err
	}
	ret.D = new(big.Int).Exp(pp.G, m, pp.N)
	proof, err := PoKEStarProve(pp, ret.D, m)
	if err != nil {
		return nil, err
	}
	ret.pi1 = proof

	var l, xl, gamma, z, z2e, omega, omegaPrime, temp big.Int
	transcript := fiatshamir.InitTranscript([]string{"ZKPoKDE", pp.G.String(), pp.H.String(),
		pp.N.String(), C1.String(), C1.String(), e.String(), ret.pi1.Q.String(), ret.pi1.R.String(), ret.D.String()}, fiatshamir.Max252)
	l.Set(transcript.GetPrimeChallengeUsingTranscript())
	gamma.Set(transcript.GetLargeChallengeUsingTranscript(length))

	// z = x*l + m + gamma E = g^{z^e}
	xl.Mul(x, &l)
	z.Add(&xl, m)
	z.Add(&z, &gamma)
	z2e.Exp(&z, e, nil)
	ret.E = new(big.Int).Exp(pp.G, &z2e, pp.N)
	temp.Exp(&l, e, nil)
	ret.K = new(big.Int).Exp(C2, &temp, pp.N)
	temp1Proof, err := PoEProve(C2, pp.N, ret.K, new(big.Int).Set(&temp))
	if err != nil {
		return nil, err
	}
	ret.pi2 = temp1Proof
	// omega = z^e - (xl)^e
	omega.Exp(&xl, e, nil)
	omega.Sub(&z2e, &omega)
	ret.F = new(big.Int).Exp(pp.G, &omega, pp.N)
	temp.Add(m, &gamma)
	omegaPrime.Div(&omega, &temp)
	temp2Proof, err := ZKPoKEProve(pp, new(big.Int).Exp(pp.G, &temp, pp.N), &omegaPrime, ret.F)
	if err != nil {
		return nil, err
	}
	ret.pi3 = temp2Proof

	// temp = C1^l * D * g^gamma = g^z
	temp3Proof, err := PoKDEProve(pp, new(big.Int).Exp(pp.G, &z, pp.N), ret.F, &z, e)
	if err != nil {
		return nil, err
	}
	ret.pi4 = temp3Proof

	return &ret, nil
}

// ZKPoKDEVerify checks C1=g^x, C2=g^{x^e}, returns true is everything is correct
func ZKPoKDEVerify(pp *PublicParameters, C1, C2, e *big.Int, proof *ZKPoKDEProof) bool {
	if pp == nil || proof == nil || proof.pi1 == nil || proof.pi2 == nil || proof.pi3 == nil || proof.pi4 == nil {
		return false
	}

	if PoKEStarVerify(pp, proof.D, proof.pi1) != true {
		return false
	}
	var l, gamma, temp big.Int
	length := 2048 + 256
	transcript := fiatshamir.InitTranscript([]string{"ZKPoKDE", pp.G.String(), pp.H.String(),
		pp.N.String(), C1.String(), C1.String(), e.String(), proof.pi1.Q.String(), proof.pi1.R.String(), proof.D.String()}, fiatshamir.Max252)
	l.Set(transcript.GetPrimeChallengeUsingTranscript())
	gamma.Set(transcript.GetLargeChallengeUsingTranscript(length))
	temp.Mul(proof.F, proof.K)
	temp.Mod(&temp, pp.N)
	if temp.Cmp(proof.E) != 0 {
		return false
	}

	temp.Exp(&l, e, nil)
	if PoEVerify(C2, pp.N, proof.K, &temp, proof.pi2) != true {
		return false
	}
	//temp = D * g^gamma
	temp.Exp(pp.G, &gamma, pp.N)
	temp.Mul(&temp, proof.D)
	temp.Mod(&temp, pp.N)
	if ZKPoKEVerify(pp, &temp, proof.F, proof.pi3) != true {
		return false
	}
	//temp = C1^l * D * g^gamma
	temp.Mul(&temp, new(big.Int).Exp(C1, &l, pp.N))
	temp.Mod(&temp, pp.N)
	if PoKDEVerify(pp, &temp, proof.E, e, proof.pi4) != true {
		return false
	}

	return true
}
