package vss

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto/curves"
)

// verifiable secret sharing scheme
type Feldman struct {
	threshold int // power of polynomial add one
	limit     int //
	curve     elliptic.Curve
}

// NewFeldman
func NewFeldman(threshold, limit int, curve elliptic.Curve) (*Feldman, error) {
	if threshold < 2 {
		return nil, fmt.Errorf("threshold least than 2")
	}
	if limit < threshold {
		return nil, fmt.Errorf("NewFeldman error, limit less than threshold")
	}
	return &Feldman{threshold, limit, curve}, nil
}

// Evaluate return verifiers and shares
// Evaluate 函数:
// 初始化多项式并使用秘密作为自由项。
// 为每个参与者计算份额，并将这些份额存储在一个列表中。
// 计算每个多项式系数的椭圆曲线上的点，作为验证者。
func (fm *Feldman) Evaluate(secret *big.Int) ([]*curves.ECPoint, []*Share, error) {
	poly, err := InitPolynomial(fm.curve, secret, fm.threshold-1)
	if err != nil {
		return nil, nil, err
	}
	shares := make([]*Share, fm.limit)
	for i := 1; i <= fm.limit; i++ {
		shares[i-1] = poly.EvaluatePolynomial(big.NewInt(int64(i)))
	}
	verifiers := make([]*curves.ECPoint, len(poly.Coefficients))
	for i, c := range poly.Coefficients {
		verifiers[i] = curves.ScalarToPoint(fm.curve, c)
	}
	return verifiers, shares, nil
}

// Verify check feldman verifiable secret sharing

// Verify 函数:
// 使用提供的份额和验证者来验证份额的正确性。
// 计算左侧（lhs）为份额在椭圆曲线上的点。
// 计算右侧（rhs）为多项式在给定点的值的椭圆曲线上的点。
// 比较左侧和右侧是否相等。
func (fm *Feldman) Verify(share *Share, verifiers []*curves.ECPoint) (bool, error) {
	if len(verifiers) < fm.threshold {
		return false, fmt.Errorf("feldman verify number error")
	}
	lhs := curves.ScalarToPoint(fm.curve, share.Y)

	var err error
	x := big.NewInt(1)
	rhs := verifiers[0]
	for j := 1; j < len(verifiers); j++ {
		x = new(big.Int).Mul(x, share.Id)
		c := verifiers[j].ScalarMult(x)
		rhs, err = rhs.Add(c)
		if err != nil {
			return false, err
		}
	}
	return lhs.Equals(rhs), nil
}
