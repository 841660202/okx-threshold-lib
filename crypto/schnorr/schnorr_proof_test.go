package schnorr

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
)

func TestProof(t *testing.T) {
	q := secp256k1.S256().N
	x := crypto.RandomNum(q)
	X := curves.ScalarToPoint(secp256k1.S256(), x)
	proof, _ := Prove(x, X) // 使用私钥生成证明

	res := Verify(proof, X) // 使用公钥来验证
	if !res {
		t.Fatal("result should be true")
	}
}

func TestProofFaulty(t *testing.T) {
	forbidden := big.NewInt(0)
	infinity_point := &curves.ECPoint{Curve: secp256k1.S256(),
		X: big.NewInt(0), Y: big.NewInt(1)}
	X := &curves.ECPoint{Curve: secp256k1.S256(),
		X: big.NewInt(0), Y: big.NewInt(1)}
	fmt.Println("infinity_point =", infinity_point)
	fmt.Println("X =", X)
	proof := &Proof{
		R: infinity_point,
		S: forbidden,
	}
	res := Verify(proof, X)
	if res {
		t.Fatal("result should be false")
	}
}
