package paillier

import (
	"fmt"
	"math/big"
	"testing"
)

func TestPaillier(t *testing.T) {
	privateKey, publicKey, _ := NewKeyPair(8)

	num1 := big.NewInt(10)
	num2 := big.NewInt(32)
	c1, _, _ := publicKey.Encrypt(num1)
	c2, _, _ := publicKey.Encrypt(num2)
	// 同态相加
	ciphered, _ := publicKey.HomoAdd(c1, c2)
	fmt.Println("ciphered: ", ciphered)
	plain, _ := privateKey.Decrypt(ciphered)
	fmt.Println("plain: ", plain)

}

func TestNIZK(t *testing.T) {
	privateKey, publicKey, _ := NewKeyPair(8)

	fmt.Println("privateKey.N: ", privateKey.N)
	fmt.Println("privateKey.Phi: ", privateKey.Phi)
	proof, _ := NIZKProof(privateKey.N, privateKey.Phi)
	fmt.Println("proof: ", proof)

	verify := NIZKVerify(publicKey.N, proof)
	fmt.Println("verify: ", verify)
}
