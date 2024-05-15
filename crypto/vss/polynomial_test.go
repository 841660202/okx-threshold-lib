package vss

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
)

func TestPoly(t *testing.T) {
	ec := secp256k1.S256()

	secret := big.NewInt(int64(1))
	polynomial, _ := InitPolynomial(ec, secret, 5)
	fmt.Println(polynomial.Coefficients)

	x := big.NewInt(int64(1))
	result := polynomial.EvaluatePolynomial(x)
	fmt.Println(result)
}

func TestLagrangian(t *testing.T) {
	ec := secp256k1.S256()
	degree := 5
	secret := big.NewInt(int64(123456))
	polynomial, _ := InitPolynomial(ec, secret, degree)
	fmt.Println(polynomial.Coefficients)

	pointList := make([]*Share, degree+1)
	for i := 0; i < degree+1; i++ {
		x := big.NewInt(int64(10 + i))
		pointList[i] = polynomial.EvaluatePolynomial(x)
	}
	recoverSecret := RecoverSecret(ec, pointList)
	fmt.Println(recoverSecret)
}

func TestFeldman(t *testing.T) {
	curve := secp256k1.S256()
	secret := big.NewInt(int64(123456))

	feldman, _ := NewFeldman(2, 3, curve)
	verifiers, shares, _ := feldman.Evaluate(secret)
	fmt.Println("=========== verifiers ===========")
	fmt.Println(verifiers)
	fmt.Println("=========== shares ===========")
	fmt.Println(shares)
	fmt.Println("=========== Verify ===========")

	verify, _ := feldman.Verify(shares[0], verifiers)
	fmt.Println(verify)
	verify, _ = feldman.Verify(shares[1], verifiers)
	fmt.Println(verify)
	verify, _ = feldman.Verify(shares[2], verifiers)
	fmt.Println(verify)
	// 注释：计算w21和w23
	fmt.Println("=========== Feldman 的可验证秘密共享 (VSS) 是一种加密协议，使交易者能够在一组参与者之间分发秘密，这样只有在最少数量的参与方合作的情况下才能重建秘密 ===========")
	fmt.Println("=========== w21 w23 ===========")
	w21 := CalLagrangian(curve, big.NewInt(int64(1)), shares[0].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(3))})
	w23 := CalLagrangian(curve, big.NewInt(int64(3)), shares[2].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(3))})
	fmt.Println(new(big.Int).Mod(new(big.Int).Add(w21, w23), curve.N))

	// 注释：计算w12和w13
	fmt.Println("=========== w12 w13 no===========")
	w12 := CalLagrangian(curve, big.NewInt(int64(2)), shares[1].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(2))})
	w13 := CalLagrangian(curve, big.NewInt(int64(3)), shares[2].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(2))})
	fmt.Println(new(big.Int).Mod(new(big.Int).Add(w12, w13), curve.N))
	// 为什么只有 计算w21和w23 可以得到正确的结果，而计算w12和w13得到的结果是错误的？
	// 因为w21和w23是在同一个多项式中计算的，而w12和w13是在不同的多项式中计算的。
	// 由于多项式的不同，导致了计算结果的不同。
	// 不是任意两个点都可以计算出正确的结果，而是要在同一个多项式中计算出来的点才能得到正确的结果。
	// 这就是为什么只有计算w21和w23可以得到正确的结果，而计算w12和w13得到的结果是错误的。
	// 除了这两个点之外，还有其他的点可以计算出正确的结果吗？
	// 可以，只要是在同一个多项式中计算出来的点，都可以得到正确的结果。

	// 例子：计算w31和w32
	fmt.Println("=========== w31 w32 ===========")
	w31 := CalLagrangian(curve, big.NewInt(int64(1)), shares[0].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(2))})
	w32 := CalLagrangian(curve, big.NewInt(int64(2)), shares[1].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(2))})
	fmt.Println(new(big.Int).Mod(new(big.Int).Add(w31, w32), curve.N))

	// 例子：计算w11和w22 no
	fmt.Println("=========== w11 w22 no===========")
	w11 := CalLagrangian(curve, big.NewInt(int64(1)), shares[0].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(1))})
	w22 := CalLagrangian(curve, big.NewInt(int64(2)), shares[1].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(1))})
	fmt.Println(new(big.Int).Mod(new(big.Int).Add(w11, w22), curve.N))

	// 例子：计算w11和w33
	fmt.Println("=========== w11 w33 ===========")
	w11 = CalLagrangian(curve, big.NewInt(int64(1)), shares[0].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(3))})
	w33 := CalLagrangian(curve, big.NewInt(int64(3)), shares[2].Y, []*big.Int{big.NewInt(int64(1)), big.NewInt(int64(3))})
	fmt.Println(new(big.Int).Mod(new(big.Int).Add(w11, w33), curve.N))

	// 为什么w11和w22计算出来的结果是错误的？
	// 因为w11和w22是在不同的多项式中计算的，而不是在同一个多项式中计算的。
	// 由于多项式的不同，导致了计算结果的不同。
	// 不是任意两个点都可以计算出正确的结果，而是要在同一个多项式中计算出来的点才能得到正确的结果。
	// 这就是为什么w11和w22计算出来的结果是错误的。

	// 怎么判断两个点是否在同一个多项式中？
	// 通过两个点的x坐标是否相等来判断两个点是否在同一个多项式中。
	// 如果两个点的x坐标相等，那么这两个点就在同一个多项式中。
	// 如果两个点的x坐标不相等，那么这两个点就不在同一个多项式中。

}
