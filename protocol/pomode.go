package protocol

import (
	"crypto/rand"
	"math/big"
)

// ZKPoMoDE contains the proofs for PoMoDE: proof of modular double exponent
type ZKPoMoDEProof struct {
	D   *big.Int
	C2  *big.Int
	pi1 *PoKEStarProof
	pi2 *ZKPoKDEProof
	pi3 *ZKPoKEModProof
}

func ZKPoMoDEProve(pp *PublicParameters, C, n, e, xmod, x *big.Int) (*ZKPoMoDEProof, error) {
	var ret ZKPoMoDEProof
	length := 2048 + 256
	var b, sum, sum2e, temp big.Int
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

	// sum = mn + x, sum2e = sum^e temp = C*D^n
	sum.Mul(m, n)
	sum.Add(&sum, x)
	sum2e.Exp(&sum, e, nil)
	temp.Exp(ret.D, n, pp.N)
	temp.Mul(&temp, C)
	temp.Mod(&temp, pp.N)
	ret.C2 = new(big.Int).Exp(pp.G, &sum2e, pp.N)
	tempProof1, err := ZKPoKDEProve(pp, &temp, ret.C2, &sum, e)
	if err != nil {
		return nil, err
	}
	ret.pi2 = tempProof1

	tempProof2, err := ZKPoKEModProve(pp, ret.C2, &sum2e, n, xmod)
	if err != nil {
		return nil, err
	}
	ret.pi3 = tempProof2
	return &ret, nil
}

func ZKPoMoDEVerify(pp *PublicParameters, C, n, e, xmod *big.Int, proof *ZKPoMoDEProof) bool {
	if proof == nil || proof.pi1 == nil || proof.pi2 == nil || proof.pi3 == nil {
		return false
	}
	if PoKEStarVerify(pp, proof.D, proof.pi1) == false {
		return false
	}
	// temp = C*D^n
	var temp big.Int
	temp.Exp(proof.D, n, pp.N)
	temp.Mul(&temp, C)
	temp.Mod(&temp, pp.N)
	if ZKPoKDEVerify(pp, &temp, proof.C2, e, proof.pi2) == false {
		return false
	}

	if ZKPoKEModVerify(pp, proof.C2, n, xmod, proof.pi3) == false {
		return false
	}
	return true
}

// ZKPoMoDE contains the proofs for PoMoDE: proof of modular double exponent
type ZKPoMoDEFastProof struct {
	pi1 *ZKPoKDEProof
	pi2 *ZKPoKEModProof
}

func ZKPoMoDEFastProve(pp *PublicParameters, C1, C2, n, e, xmod, x *big.Int) (*ZKPoMoDEFastProof, error) {
	var ret ZKPoMoDEFastProof
	tempProof1, err := ZKPoKDEProve(pp, C1, C2, x, e)
	if err != nil {
		return nil, err
	}
	ret.pi1 = tempProof1

	tempProof2, err := ZKPoKEModProve(pp, C2, new(big.Int).Exp(x, e, nil), n, xmod)
	if err != nil {
		return nil, err
	}
	ret.pi2 = tempProof2
	return &ret, nil
}

func ZKPoMoDEFastVerify(pp *PublicParameters, C1, C2, n, e, xmod *big.Int, proof *ZKPoMoDEFastProof) bool {
	if proof == nil || proof.pi1 == nil || proof.pi2 == nil {
		return false
	}
	if ZKPoKDEVerify(pp, C1, C2, e, proof.pi1) == false {
		return false
	}
	if ZKPoKEModVerify(pp, C2, n, xmod, proof.pi2) == false {
		return false
	}
	return true
}
