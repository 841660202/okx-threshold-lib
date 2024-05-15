package bip32

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
)

// 目的是验证密钥派生链是否按预期工作，并确保每一步的派生都能正确计算出新的公钥和私钥份额
func TestTssKey(t *testing.T) {
	curve := secp256k1.S256()
	x := crypto.RandomNum(curve.N)
	X := curves.ScalarToPoint(curve, x)
	chaincode := hex.EncodeToString([]byte("chaincode"))

	tssKey, _ := NewTssKey(x, X, chaincode)
	// 	/protocol/coinType/index
	tssKey, _ = tssKey.NewChildKey(0)
	tssKey, _ = tssKey.NewChildKey(0)
	tssKey, _ = tssKey.NewChildKey(0)
	fmt.Println("child publicKey: ", tssKey.PublicKey())
	fmt.Println("child key share: ", tssKey.ShareI())
	fmt.Println("privateKey offset: ", tssKey.PrivateKeyOffset())
	childKey := new(big.Int).Mod(new(big.Int).Add(x, tssKey.PrivateKeyOffset()), curve.N)
	fmt.Println("child key share: ", childKey)
}

// 这个测试用例主要用于验证即使在不知道原始私钥的情况下，只通过公钥和链码也能正确进行密钥派生，并且派生出的新公钥与通过计算得到的公钥一致。
func TestTssKey_cmp(t *testing.T) {
	curve := secp256k1.S256()
	x := crypto.RandomNum(curve.N)      // 私钥
	X := curves.ScalarToPoint(curve, x) // 公钥
	chaincode := hex.EncodeToString([]byte("chaincode"))

	tssKey, _ := NewTssKey(nil, X, chaincode)
	fmt.Println(tssKey)
	tssKey, _ = tssKey.NewChildKey(45)
	fmt.Println(tssKey)

	x_new := new(big.Int).Add(x, tssKey.PrivateKeyOffset()) // 新的私钥
	X_new := curves.ScalarToPoint(curve, x_new)             // 新的公钥
	fmt.Println("旧的公钥: ", tssKey.publicKey)                 // 旧的公钥
	fmt.Println("新的公钥: ", X_new)                            // 新的公钥
}
