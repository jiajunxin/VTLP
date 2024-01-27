package protocol

import (
	"fmt"
	"math/big"
)

// RSAExpProof contains the public/private parts of an RSA key, RSAMod = P*Q, D=publicKey(default 17), D*E = 1 mod phi(N)
type RSAExpProof struct {
	RSAMod *big.Int
	Base   *big.Int
	P      *big.Int
	Q      *big.Int
	D      *big.Int
	E      *big.Int
	//Order is the order of subgroup QR_N
	Order    *big.Int
	Exponent *big.Int // Exponent  = 2^TimePara mod Order
}

func RSAExpSetup() *RSAExpProof {
	var ret RSAExpProof
	// ret.P = *getSafePrime()
	// ret.Q = *getSafePrime()
	ret.P = new(big.Int)
	ret.Q = new(big.Int)
	ret.P.SetString(Pstring, 10)
	ret.Q.SetString(Qstring, 10)
	ret.RSAMod = new(big.Int).Mul(ret.P, ret.Q)
	var ptemp, qtemp big.Int
	ptemp.Sub(ret.P, big1)
	ptemp.Div(&ptemp, big2)
	qtemp.Sub(ret.Q, big1)
	qtemp.Div(&qtemp, big2)
	ret.Order = new(big.Int).Mul(&ptemp, &qtemp)
	ret.Base = getRanQR(ret.P, ret.Q)

	var temp, big4, useless big.Int
	big4.SetInt64(4)
	ret.D = new(big.Int).SetInt64(publicKey)
	ret.E = new(big.Int)
	temp.GCD(&useless, ret.E, new(big.Int).Mul(ret.Order, &big4), ret.D)
	if temp.Cmp(new(big.Int).SetInt64(1)) != 0 {
		fmt.Println("Error while setting up keys!")
		fmt.Println("e = ", ret.E.String())
		ret.E.Mod(ret.E, new(big.Int).Mul(ret.Order, &big4))
		fmt.Println("e = ", ret.E.String())
		temp.Mul(ret.D, ret.E)
		temp.Mod(&temp, new(big.Int).Mul(ret.Order, &big4))
		fmt.Println("temp = ", temp.String())
	}
	temp.SetInt64(TimePara)
	ret.Exponent = new(big.Int).Exp(big2, &temp, ret.Order)
	return &ret
}
