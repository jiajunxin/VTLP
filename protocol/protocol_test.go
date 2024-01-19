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

func TestZKPoKE2(t *testing.T) {
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
