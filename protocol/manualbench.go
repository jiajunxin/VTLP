package protocol

import (
	"fmt"
	"math/big"
	"runtime"
	"strconv"
	"time"
)

// ManualBench is used for manual benchmark. Because the running time can be long, the golang benchmark may not work
func ManualBench(counter int) {
	setup := *TrustedSetup()
	startingTime := time.Now().UTC()
	TimeLockPuzzleManualBenchmark(&setup, counter)
	endingTime := time.Now().UTC()
	var duration = endingTime.Sub(startingTime)
	fmt.Printf("Running TimeLockPuzzleManualBenchmark with squaring %v\n times, Takes [%.3f] Seconds \n",
		counter, duration.Seconds())
	runtime.GC()
	ComputeLargeExpManualBenchmark(&setup, 17) // 65537 = 2^16 +1, the smallest secure public key size for RSA signature
}

// TimeLockPuzzleManualBenchmark is used for manual benchmark because its running time can be long and varies.
// This function tests the time it takes to compute g^{2^{counter}} mod N
func TimeLockPuzzleManualBenchmark(setup *Setup, counter int) {
	var solution big.Int
	solution.Set(setup.G)
	for i := 0; i < counter; i++ {
		solution.Exp(&solution, big2, setup.N)
	}
}

// ComputeLargeExpManualBenchmark is used for manual benchmark because its running time can be long and varies.
// This function tests the time it takes to compute doubleExp = g^{exponent} and g^{doubleExp} mod N
func ComputeLargeExpManualBenchmark(setup *Setup, exponent int) {
	var doubleExp big.Int
	var exp big.Int
	exp.SetInt64(int64(exponent))
	var temp big.Int //temp needs around 2000 bits, any non-trivial random number works as a benchmark
	temp.Set(setup.G)
	startingTime := time.Now().UTC()
	doubleExp = *setup.G.Exp(&temp, &exp, nil)
	endingTime := time.Now().UTC()
	var duration = endingTime.Sub(startingTime)
	fmt.Printf("Running doubleExp = g^{exponent} with exponent %v\n , Takes [%.3f] Seconds \n",
		exponent, duration.Seconds())

	startingTime = time.Now().UTC()
	_ = *setup.G.Exp(setup.G, &doubleExp, setup.N)
	endingTime = time.Now().UTC()
	duration = endingTime.Sub(startingTime)
	fmt.Printf("Running g^{doubleExp} mod N , Takes [%.3f] Seconds \n",
		duration.Seconds())
}

// GenBenchSet generate one set where every element is different
func GenBenchSet(num int) []string {
	ret := make([]string, num)
	for i := 0; i < num; i++ {
		ret[i] = strconv.Itoa(i)
	}
	return ret
}
