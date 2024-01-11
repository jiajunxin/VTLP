module github.com/PoMoDE

go 1.19

require (
	github.com/consensys/gnark-crypto v0.10.0
	github.com/remyoudompheng/bigfft v0.0.0-20220927061507-ef77025ab5aa
)

require (
	github.com/stretchr/testify v1.8.2 // indirect
	golang.org/x/sys v0.7.0 // indirect
)

replace (
	github.com/consensys/gnark => github.com/bnb-chain/gnark v0.7.1-0.20230203031713-0d81c67d080a
	github.com/consensys/gnark-crypto => github.com/bnb-chain/gnark-crypto v0.7.1-0.20230203031630-7c643ad11891
)

