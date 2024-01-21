package protocol

import (
	"math/big"
	"testing"
)

func TestPoKEStar(t *testing.T) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var exponent, C big.Int
	exponent.SetInt64(666)
	C.Exp(setup.G, &exponent, setup.N)
	proof, err := PoKEStarProve(&pp, &C, &exponent)
	if err != nil {
		t.Errorf("error not empty for TestPoKEStar")
	}
	flag := PoKEStarVerify(&pp, &C, proof)
	if flag != true {
		t.Errorf("did not pass verification")
	}

	exponent.SetInt64(667)
	proof, err = PoKEStarProve(&pp, &C, &exponent)
	if err == nil {
		t.Errorf("error empty when it should not for TestPoKEStar")
	}
	C.Exp(setup.G, &exponent, setup.N)
	proof, err = PoKEStarProve(&pp, &C, &exponent)
	if err != nil {
		t.Errorf("error not empty for TestPoKEStar")
	}
	exponent.SetInt64(66777)
	C.Exp(setup.G, &exponent, setup.N)
	flag = PoKEStarVerify(&pp, &C, proof)
	if flag == true {
		t.Errorf("pass verification when it should not")
	}
}

func TestZKPoKE(t *testing.T) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var exponent, C big.Int
	exponent.SetInt64(666)
	C.Exp(setup.G, &exponent, setup.N)
	proof, err := ZKPoKEProve(&pp, pp.G, &exponent, &C)
	if err != nil {
		t.Errorf("error not empty for TestPoKEStar")
	}
	flag := ZKPoKEVerify(&pp, pp.G, &C, proof)
	if flag != true {
		t.Errorf("did not pass verification")
	}

	exponent.SetInt64(667)
	proof, err = ZKPoKEProve(&pp, pp.G, &exponent, &C)
	if err == nil {
		t.Errorf("error empty when it should not for TestPoKEStar")
	}
	C.Exp(setup.G, &exponent, setup.N)
	proof, err = ZKPoKEProve(&pp, pp.G, &exponent, &C)
	if err != nil {
		t.Errorf("error not empty for TestPoKEStar")
	}
	exponent.SetInt64(66777)
	C.Exp(setup.G, &exponent, setup.N)
	flag = ZKPoKEVerify(&pp, pp.G, &C, proof)
	if flag == true {
		t.Errorf("pass verification when it should not")
	}
}

func TestZKPoKEMod(t *testing.T) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var x, C, n, xmod big.Int //x mod n = xmod
	x.SetInt64(666)
	n.SetInt64(10)
	xmod.SetInt64(6)
	C.Exp(setup.G, &x, setup.N)
	proof, err := ZKPoKEModProve(&pp, &C, &x, &n, &xmod)
	if err != nil {
		t.Errorf("error not empty for TestPoKEStar")
	}
	flag := ZKPoKEModVerify(&pp, &C, &n, &xmod, proof)
	if flag != true {
		t.Errorf("did not pass verification")
	}

	x.SetInt64(667)
	proof, err = ZKPoKEModProve(&pp, &C, &x, &n, &xmod)
	if err == nil {
		t.Errorf("error empty when it should not for TestPoKEStar")
	}
	C.Exp(setup.G, &x, setup.N)
	proof, err = ZKPoKEModProve(&pp, &C, &x, &n, &xmod)
	if err == nil {
		t.Errorf("error empty when it should not for TestPoKEStar")
	}
	x.SetInt64(66777)
	C.Exp(setup.G, &x, setup.N)
	flag = ZKPoKEModVerify(&pp, &C, &n, &xmod, proof)
	if flag == true {
		t.Errorf("pass verification when it should not")
	}
}

func TestPoE(t *testing.T) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var exponent, C big.Int
	exponent.SetInt64(666)
	C.Exp(setup.G, &exponent, setup.N)
	proof, err := PoEProve(pp.G, pp.N, &C, &exponent)
	if err != nil {
		t.Errorf("error not empty for TestPoKEStar")
	}
	flag := PoEVerify(pp.G, pp.N, &C, &exponent, proof)
	if flag != true {
		t.Errorf("did not pass verification")
	}

	exponent.SetInt64(123777)
	flag = PoEVerify(pp.G, pp.N, &C, &exponent, proof)
	if flag == true {
		t.Errorf("pass verification when it should not")
	}
}

func TestPoKDE(t *testing.T) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var x, C1, C2, e, xe big.Int //xe = x^e
	x.SetInt64(666)
	e.SetInt64(17)
	xe.Exp(&x, &e, nil)
	C1.Exp(setup.G, &x, setup.N)
	C2.Exp(setup.G, &xe, setup.N)
	proof, err := PoKDEProve(&pp, &C1, &C2, &x, &e)
	if err != nil {
		t.Errorf("error not empty for TestPoKEStar")
	}
	flag := PoKDEVerify(&pp, &C1, &C2, &e, proof)
	if flag != true {
		t.Errorf("did not pass verification")
	}

	x.SetInt64(66777)
	C2.Exp(setup.G, &x, setup.N)
	flag = PoKDEVerify(&pp, &C1, &C2, &e, proof)
	if flag == true {
		t.Errorf("pass verification when it should not")
	}
}

func TestZKPoKDE(t *testing.T) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var x, C1, C2, e, xe big.Int //xe = x^e
	x.SetInt64(666)
	e.SetInt64(17)
	xe.Exp(&x, &e, nil)
	C1.Exp(setup.G, &x, setup.N)
	C2.Exp(setup.G, &xe, setup.N)
	proof, err := ZKPoKDEProve(&pp, &C1, &C2, &x, &e)
	if err != nil {
		t.Errorf("error not empty for TestPoKEStar")
	}
	flag := ZKPoKDEVerify(&pp, &C1, &C2, &e, proof)
	if flag != true {
		t.Errorf("did not pass verification")
	}

	x.SetInt64(66777)
	C2.Exp(setup.G, &x, setup.N)
	flag = ZKPoKDEVerify(&pp, &C1, &C2, &e, proof)
	if flag == true {
		t.Errorf("pass verification when it should not")
	}
}

func TestZKPoMoDE(t *testing.T) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var x, C1, C2, e, x2e, n, xmod big.Int //x2e = x^e
	x.SetInt64(6)
	e.SetInt64(7)
	n.SetInt64(10)
	x2e.Exp(&x, &e, nil) //6^7 = 279936
	xmod.Mod(&x2e, &n)
	C1.Exp(setup.G, &x, setup.N)
	C2.Exp(setup.G, &x2e, setup.N)
	proof, err := ZKPoMoDEProve(&pp, &C1, &n, &e, &xmod, &x)
	if err != nil {
		t.Errorf("error not empty for TestPoKEStar")
	}
	flag := ZKPoMoDEVerify(&pp, &C1, &n, &e, &xmod, proof)
	if flag != true {
		t.Errorf("did not pass verification")
	}

	x.SetInt64(66777)
	C1.Exp(setup.G, &x, setup.N)
	flag = ZKPoMoDEVerify(&pp, &C1, &n, &e, &xmod, proof)
	if flag == true {
		t.Errorf("pass verification when it should not")
	}
}

func TestZKPoMoDEFast(t *testing.T) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var x, C1, C2, e, x2e, n, xmod big.Int //xe = x^e
	x.SetInt64(6)
	e.SetInt64(7)
	n.SetInt64(10)
	x2e.Exp(&x, &e, nil) //6^7 = 279936
	xmod.SetInt64(6)
	C1.Exp(setup.G, &x, setup.N)
	C2.Exp(setup.G, &x2e, setup.N)
	proof, err := ZKPoMoDEFastProve(&pp, &C1, &C2, &n, &e, &xmod, &x)
	if err != nil {
		t.Errorf("error not empty for TestPoKEStar")
	}
	flag := ZKPoMoDEFastVerify(&pp, &C1, &C2, &n, &e, &xmod, proof)
	if flag != true {
		t.Errorf("did not pass verification")
	}

	x.SetInt64(66777)
	C1.Exp(setup.G, &x, setup.N)
	flag = ZKPoMoDEFastVerify(&pp, &C1, &C2, &n, &e, &xmod, proof)
	if flag == true {
		t.Errorf("pass verification when it should not")
	}
}
