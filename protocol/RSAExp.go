package protocol

import (
	"fmt"
	"math/big"
)

// RSAExpProof contains the public/private parts of an RSA key
type RSAExpProof struct {
	RSAMod big.Int
	Base   big.Int
	P      big.Int
	Q      big.Int
	//Order is the order of subgroup QR_N
	Order    big.Int
	Exponent big.Int
}

func RSAExpSetup() *RSAExpProof {
	var ret RSAExpProof
	// ret.P = *getSafePrime()
	// ret.Q = *getSafePrime()
	ret.P.SetString(PString, 10)
	ret.Q.SetString(Qstring, 10)
	ret.RSAMod.Mul(&ret.P, &ret.Q)
	fmt.Println("Bit length of RSAMod = ", ret.RSAMod.BitLen())
	var ptemp, qtemp big.Int
	ptemp.Sub(&ret.P, big1)
	ptemp.Div(&ptemp, big2)
	qtemp.Sub(&ret.Q, big1)
	qtemp.Div(&qtemp, big2)
	ret.Order.Mul(&ptemp, &qtemp)
	ret.Base = *getRanQR(&ret.P, &ret.Q)

	var temp big.Int
	temp.SetInt64(TimePara)
	ret.Exponent.Exp(big2, &temp, &ret.Order)
	return &ret
}

func GetSquares(base, mod *big.Int) []big.Int {
	ret := make([]big.Int, RSABitLength)
	ret[0].Set(base)
	for i := 1; i < mod.BitLen(); i++ {
		ret[i].Exp(&ret[i-1], big2, mod)
	}
	return ret
}

func GetProd(base, exp, mod *big.Int) *big.Int {
	var prod big.Int

	squares := make([]big.Int, mod.BitLen())
	squares[0].Set(base)
	for i := 1; i < mod.BitLen(); i++ {
		squares[i].Exp(&squares[i-1], big2, mod)
	}

	bitLen := exp.BitLen()
	prod.Set(big1)
	for i := 0; i < bitLen; i++ {
		if exp.Bit(i) == 1 {
			prod.Mul(&prod, &squares[i])
		}
	}
	return &prod
}
