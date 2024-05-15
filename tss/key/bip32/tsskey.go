package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto/curves"
)

var label = []byte("Key share derivation:\n")

// support secp256k1 derived, not support ed25519
type TssKey struct {
	shareI       *big.Int        // key share
	publicKey    *curves.ECPoint // publicKey
	chaincode    []byte
	offsetSonPri *big.Int // child private key share offset, accumulative
}

// NewTssKey shareI is optional
func NewTssKey(shareI *big.Int, publicKey *curves.ECPoint, chaincode string) (*TssKey, error) {
	chainBytes, err := hex.DecodeString(chaincode)
	if err != nil {
		return nil, err
	}
	if publicKey == nil || chaincode == "" {
		return nil, fmt.Errorf("parameter error")
	}
	tssKey := &TssKey{
		shareI:       shareI,
		publicKey:    publicKey,
		chaincode:    chainBytes,
		offsetSonPri: big.NewInt(0),
	}
	return tssKey, nil
}

// NewChildKey like bip32 non-hardened derivation
func (tssKey *TssKey) NewChildKey(childIdx uint32) (*TssKey, error) {
	if childIdx >= uint32(0x80000000) { // 2^31
		return nil, fmt.Errorf("hardened derivation is unsupported")
	}
	curve := tssKey.publicKey.Curve
	intermediary, err := calPrivateOffset(tssKey.publicKey.X.Bytes(), tssKey.chaincode, childIdx)
	if err != nil {
		return nil, err
	}

	// Validate key
	err = validatePrivateKey(intermediary[:32])
	if err != nil {
		return nil, err
	}

	offset := new(big.Int).SetBytes(intermediary[:32])
	point := curves.ScalarToPoint(curve, offset)
	ecPoint, err := tssKey.publicKey.Add(point)
	if err != nil {
		return nil, err
	}
	shareI := tssKey.shareI
	if shareI != nil {
		shareI = new(big.Int).Add(shareI, offset)
		shareI = new(big.Int).Mod(shareI, curve.Params().N)
	}
	offsetSonPri := new(big.Int).Add(tssKey.offsetSonPri, offset)
	offsetSonPri = new(big.Int).Mod(offsetSonPri, curve.Params().N)
	tss := &TssKey{
		shareI:       shareI,
		publicKey:    ecPoint,
		chaincode:    intermediary[32:],
		offsetSonPri: offsetSonPri,
	}
	return tss, nil
}

// PrivateKeyOffset child share key offset, accumulative
func (tssKey *TssKey) PrivateKeyOffset() *big.Int {
	return tssKey.offsetSonPri
}

// ShareI child share key
func (tssKey *TssKey) ShareI() *big.Int {
	return tssKey.shareI
}

// PublicKey child publicKey
func (tssKey *TssKey) PublicKey() *curves.ECPoint {
	return tssKey.publicKey
}

// calPrivateOffset HMAC-SHA512(label | chaincode | publicKey | childIdx)
func calPrivateOffset(publicKey, chaincode []byte, childIdx uint32) ([]byte, error) {
	hash := hmac.New(sha512.New, label)
	var data []byte
	data = append(data, chaincode...)
	data = append(data, publicKey...)
	data = append(data, uint32Bytes(childIdx)...)
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func validatePrivateKey(key []byte) error {
	if fmt.Sprintf("%x", key) == "0000000000000000000000000000000000000000000000000000000000000000" || //if the key is zero
		bytes.Compare(key, secp256k1.S256().N.Bytes()) >= 0 || //or is outside of the curve
		len(key) != 32 { //or is too short
		return fmt.Errorf("Invalid private key")
	}
	return nil
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}

// 在您提供的代码中，`chaincode` 是一个用于生成密钥派生的关键参数，它在使用 HMAC-SHA512 算法进行密钥派生函数（KDF）时起到了非常重要的作用。在加密货币和密钥派生领域，特别是在 BIP32 标准中，`chaincode` 通常用于增加密钥派生的安全性。

// ### 作用和意义
// `chaincode` 作为一个额外的熵源（随机性来源），在密钥派生过程中与公钥和子索引（child index）一起被用来生成新的子密钥。这样做的目的是为了确保每一次的密钥派生都是独一无二的，即使是使用相同的公钥和子索引，只要 `chaincode` 不同，派生出的结果也会不同。这增加了密钥派生过程的安全性，防止了潜在的重放攻击和其他相关的安全威胁。

// ### 在代码中的应用
// 在您的代码中，`chaincode` 被用作 HMAC-SHA512 哈希函数的一个输入，具体在 `calPrivateOffset` 函数中实现。这个函数将 `chaincode`、公钥和子索引组合在一起，生成一个 512 位的哈希值，这个哈希值后续被用来生成新的子密钥和新的 `chaincode`。

// ```go
// func calPrivateOffset(publicKey, chaincode []byte, childIdx uint32) ([]byte, error) {
//     hash := hmac.New(sha512.New, label)
//     var data []byte
//     data = append(data, chaincode...)
//     data = append(data, publicKey...)
//     data = append(data, uint32Bytes(childIdx)...)
//     _, err := hash.Write(data)
//     if err != nil {
//         return nil, err
//     }
//     return hash.Sum(nil), nil
// }
// ```

// 在这个函数中，`chaincode` 被首先加入到数据缓冲区，然后是公钥和子索引的字节表示。这个组合数据被用来生成 HMAC-SHA512 哈希值，哈希值的前 256 位用于生成新的私钥偏移量，后 256 位用于更新 `chaincode`，以用于进一步的密钥派生。

// ### 总结
// `chaincode` 在 BIP32 和类似的密钥派生协议中是一个核心组件，它帮助确保了派生出的密钥具有高度的安全性和独特性。通过在密钥派生过程中使用 `chaincode`，可以有效地防止密钥重复和某些类型的攻击，从而增强整个系统的安全性。
