package protocol

import (
	"math/big"
	"testing"
)

const expBenchmark int64 = 8

func BenchmarkZKPoMoDEProve(b *testing.B) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var x, C1, C2, e, x2e, n, xmod big.Int //x2e = x^e
	x.Set(setup.G)
	e.SetInt64(expBenchmark)
	n.Set(setup.N)
	x2e.Exp(&x, &e, nil) //6^7 = 279936
	xmod.Mod(&x2e, &n)
	C1.Exp(setup.G, &x, setup.N)
	C2.Exp(setup.G, &x2e, setup.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ZKPoMoDEProve(&pp, &C1, &n, &e, &xmod, &x)
	}
}

func BenchmarkZKPoMoDEVerify(b *testing.B) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var x, C1, C2, e, x2e, n, xmod big.Int //x2e = x^e
	x.Set(setup.G)
	e.SetInt64(expBenchmark)
	n.Set(setup.N)
	x2e.Exp(&x, &e, nil) //6^7 = 279936
	xmod.Mod(&x2e, &n)
	C1.Exp(setup.G, &x, setup.N)
	C2.Exp(setup.G, &x2e, setup.N)
	proof, _ := ZKPoMoDEProve(&pp, &C1, &n, &e, &xmod, &x)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ZKPoMoDEVerify(&pp, &C1, &n, &e, &xmod, proof)
	}
}

func BenchmarkZKPoMoDEFastProve(b *testing.B) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var x, C1, C2, e, x2e, n, xmod big.Int //x2e = x^e
	x.Set(setup.G)
	e.SetInt64(expBenchmark)
	n.Set(setup.N)
	x2e.Exp(&x, &e, nil) //6^7 = 279936
	xmod.Mod(&x2e, &n)
	C1.Exp(setup.G, &x, setup.N)
	C2.Exp(setup.G, &x2e, setup.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ZKPoMoDEFastProve(&pp, &C1, &C2, &n, &e, &xmod, &x)
	}
}

func BenchmarkZKPoMoDEFastVerify(b *testing.B) {
	setup := TrustedSetup()
	pp := PublicParameters{setup.N, setup.G, setup.H}
	var x, C1, C2, e, x2e, n, xmod big.Int //x2e = x^e
	x.Set(setup.G)
	e.SetInt64(expBenchmark)
	n.Set(setup.N)
	x2e.Exp(&x, &e, nil) //6^7 = 279936
	xmod.Mod(&x2e, &n)
	C1.Exp(setup.G, &x, setup.N)
	C2.Exp(setup.G, &x2e, setup.N)
	proof, _ := ZKPoMoDEFastProve(&pp, &C1, &C2, &n, &e, &xmod, &x)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ZKPoMoDEFastVerify(&pp, &C1, &C2, &n, &e, &xmod, proof)
	}
}
