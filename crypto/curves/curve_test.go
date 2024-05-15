package curves

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto"
)

func TestCurve(t *testing.T) {
	curve := secp256k1.S256()
	x := crypto.RandomNum(curve.N)
	point := ScalarToPoint(curve, x)
	fmt.Println(point)

	ecPoint := point.ScalarMult(x)
	fmt.Println(ecPoint)

	bytes, _ := json.Marshal(ecPoint)
	fmt.Println(string(bytes))
	p := ECPoint{}
	_ = json.Unmarshal(bytes, &p)
	fmt.Println(p)

	add, _ := ecPoint.Add(&p)
	fmt.Println(add)
}

func TestPointToPubKey(t *testing.T) {
	curve := secp256k1.S256()
	x := crypto.RandomNum(curve.N)
	fmt.Println("private key: ", hex.EncodeToString(x.Bytes()))
	point := ScalarToPoint(curve, x)
	publicKey := secp256k1.PublicKey{Curve: point.Curve, X: point.X, Y: point.Y}
	fmt.Println("ecdsa publicKey: ", hex.EncodeToString(publicKey.SerializeCompressed()))

	curve2 := edwards.Edwards()
	point2 := ScalarToPoint(curve2, x)
	publicKey2 := edwards.PublicKey{Curve: point2.Curve, X: point2.X, Y: point2.Y}
	fmt.Println("ed25519 publicKey: ", hex.EncodeToString(publicKey2.SerializeCompressed()))
}

// 公钥转化成点
func TestPubKeyToPoint(t *testing.T) {
	// ecdsa publicKey:  0220dcc94db44d846a174b10765bbc2ea916988d098598eb812aaddd5c7378f29d
	point, err := EcdsaPubKeyToPoint("0220dcc94db44d846a174b10765bbc2ea916988d098598eb812aaddd5c7378f29d")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("---------")
		fmt.Println(point)
		fmt.Println("---------")
	}

	// ed25519 publicKey:  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
	point2, err := Ed25519PubKeyToPoint("bb10a2166436f1d8d1b8dc18403ed0b254b5d024e4e1b1a62d697803cb1c4379")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(point2)
	}
}

// 公钥转化成点在椭圆曲线密码学中有多个重要用途，特别是在实现和验证加密算法、签名算法以及进行密钥交换时。以下是一些具体的应用场景：

// 1. **验证签名**：
//    在数字签名算法中，如ECDSA（Elliptic Curve Digital Signature Algorithm）或EdDSA（Edwards-curve Digital Signature Algorithm），签名的验证过程需要将公钥从其序列化形式转换为椭圆曲线上的点。这个点随后用于计算签名的有效性，通过一系列的椭圆曲线点运算来确认签名是否由持有相应私钥的实体生成。

// 2. **密钥协商**：
//    在密钥交换协议中，如ECDH（Elliptic Curve Diffie-Hellman），两个参与方各自生成一个临时的公私钥对，并将公钥发送给对方。接收方将收到的公钥（通常是序列化的形式）转换为椭圆曲线上的点，然后使用自己的私钥与对方的公钥点进行运算，以生成一个共享的密钥。这个共享密钥可以用于后续的加密通信。

// 3. **加密和解密**：
//    在某些基于椭圆曲线的加密方案中，如ElGamal椭圆曲线加密，公钥被用来加密数据，而转换为点的公钥是执行加密运算的必要步骤。同样地，解密过程也需要用到椭圆曲线上的点。

// 4. **公钥验证**：
//    在某些系统中，为了确保公钥的合法性和有效性，需要将公钥从其序列化形式转换成点，并对其进行一系列的验证过程，例如检查点是否确实位于椭圆曲线上，以及是否满足曲线方程。

// 5. **区块链和加密货币**：
//    在比特币和其他基于区块链的加密货币中，公钥的转换也是验证交易的一个关键步骤。公钥点用于验证交易签名的正确性，从而确保交易的安全性和完整性。

// 总之，将公钥转化为椭圆曲线上的点是椭圆曲线密码学中的一个基础操作，对于实现安全的加密通信、数据签名和验证等功能至关重要。这一步骤确保了数字身份和数据的安全性，是现代加密系统的核心组成部分。
