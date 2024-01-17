module github.com/PoMoDE

go 1.19

require (
	github.com/consensys/gnark v0.7.0
	github.com/consensys/gnark-crypto v0.10.0
	github.com/remyoudompheng/bigfft v0.0.0-20220927061507-ef77025ab5aa
)

require (
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/rs/zerolog v1.26.1 // indirect
	github.com/stretchr/testify v1.8.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.1.0 // indirect
	golang.org/x/sys v0.7.0 // indirect
)

replace (
	github.com/consensys/gnark => github.com/bnb-chain/gnark v0.7.1-0.20230203031713-0d81c67d080a
	github.com/consensys/gnark-crypto => github.com/bnb-chain/gnark-crypto v0.7.1-0.20230203031630-7c643ad11891
)
