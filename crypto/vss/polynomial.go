package vss

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type Polynomial struct {
	Coefficients []*big.Int // polynomial coefficient, eg: [a0, a1, a2 ...]
	QMod         *big.Int
}

// secret share
type Share struct {
	Id *big.Int // x-coordinate
	Y  *big.Int // y-coordinate
}

// InitPolynomial init Coefficients [a0, a1....at] t=degree
// 多项式初始化 (InitPolynomial):

// 生成一个随机的多项式，其中第一个系数是秘密值，其余系数是随机生成的。
// 使用椭圆曲线的阶（curve.Params().N）作为模运算的基。
func InitPolynomial(curve elliptic.Curve, secret *big.Int, degree int) (*Polynomial, error) {
	if degree < 1 {
		return nil, fmt.Errorf("degree must be at least 1")
	}
	q := curve.Params().N
	Coefficients := make([]*big.Int, degree+1)
	Coefficients[0] = secret
	for i := 1; i <= degree; i++ {
		r, err := rand.Prime(rand.Reader, q.BitLen())
		if err != nil {
			return nil, err
		}
		Coefficients[i] = r // random generation coefficient
	}
	return &Polynomial{
		Coefficients: Coefficients,
		QMod:         q,
	}, nil
}

// EvaluatePolynomial a polynomial with coefficients such that:
// EvaluatePolynomial(x):
//
//	returns a + bx + cx^2 + dx^3

// 多项式评估 (EvaluatePolynomial):

// 给定一个x值，计算多项式的y值。
// 这里使用的是简单的多项式计算方法，通过连续乘以x并累加每个项的结果。
func (p *Polynomial) EvaluatePolynomial(x *big.Int) *Share {
	result := new(big.Int).Set(p.Coefficients[0])
	tmp := big.NewInt(1)
	for i := 1; i <= len(p.Coefficients)-1; i++ {
		tmp = new(big.Int).Mul(tmp, x)
		aiXi := new(big.Int).Mul(p.Coefficients[i], tmp)
		result = result.Add(result, aiXi)
	}
	result = new(big.Int).Mod(result, p.QMod)
	return &Share{
		Id: x,
		Y:  result,
	}
}

// RecoverSecret recover secret key

// 秘密恢复 (RecoverSecret):

// 使用拉格朗日插值法从多个份额中恢复原始的秘密。
// 每个份额对应一个点（x, y），通过计算所有点的加权和来恢复秘密。
func RecoverSecret(curve elliptic.Curve, pointList []*Share) *big.Int {
	q := curve.Params().N
	xList := make([]*big.Int, len(pointList))
	for i, point := range pointList {
		xList[i] = point.Id
	}
	secret := big.NewInt(0)
	for _, point := range pointList {
		wi := CalLagrangian(curve, point.Id, point.Y, xList)
		secret = secret.Add(secret, wi)
	}
	secret = new(big.Int).Mod(secret, q)
	return secret
}

// CalLagrangian lagrangian interpolation wi, x = sum(wi)
// 拉格朗日插值计算 (CalLagrangian):

// 计算每个份额的权重，权重计算依赖于所有其他份额的x值。
// 注意，这里的实现可能有误，因为coef.ModInverse(coef, q)应该在coef被计算为xj - xi之后立即调用。
func CalLagrangian(curve elliptic.Curve, x, y *big.Int, xList []*big.Int) *big.Int {
	q := curve.Params().N
	wi := new(big.Int).SetBytes(y.Bytes())
	// wi = y*mul(xj/(xj-xi))
	for i := 0; i < len(xList); i++ {
		xj := xList[i]
		if x.Cmp(xj) == 0 {
			continue
		}
		coef := new(big.Int).Sub(xj, x)
		coef.ModInverse(coef, q)
		coef.Mul(xj, coef)
		wi.Mul(wi, coef)
	}
	wi = new(big.Int).Mod(wi, q)
	return wi
}

// 您提供的代码实现了一个完整的多项式基础的秘密共享系统，使用的是椭圆曲线密码学的参数。下面是对关键部分的解释和分析。

// ### 主要组件和功能

// 1. **多项式初始化 (`InitPolynomial`)**:
//    - 生成一个随机的多项式，其中第一个系数是秘密值，其余系数是随机生成的。
//    - 使用椭圆曲线的阶（`curve.Params().N`）作为模运算的基。

// 2. **多项式评估 (`EvaluatePolynomial`)**:
//    - 给定一个x值，计算多项式的y值。
//    - 这里使用的是简单的多项式计算方法，通过连续乘以x并累加每个项的结果。

// 3. **秘密恢复 (`RecoverSecret`)**:
//    - 使用拉格朗日插值法从多个份额中恢复原始的秘密。
//    - 每个份额对应一个点（x, y），通过计算所有点的加权和来恢复秘密。

// 4. **拉格朗日插值计算 (`CalLagrangian`)**:
//    - 计算每个份额的权重，权重计算依赖于所有其他份额的x值。
//    - 注意，这里的实现可能有误，因为`coef.ModInverse(coef, q)`应该在`coef`被计算为`xj - xi`之后立即调用。

// ### 注意事项与改进建议

// 1. **错误处理**:
//    - 在`CalLagrangian`中，如果`coef.ModInverse(coef, q)`无法找到模逆（例如，当`coef`和`q`不互质时），这个函数会返回`nil`。这种情况需要额外的错误处理。

// 2. **效率问题**:
//    - 在`EvaluatePolynomial`中，每次迭代都重新计算`tmp = new(big.Int).Mul(tmp, x)`，这可能导致不必要的重复计算。可以优化为顺序计算每个项的贡献。

// 3. **安全性**:
//    - 在生成多项式系数时，使用`rand.Prime`可能不是最佳选择，因为它生成的是素数，而在多项式的上下文中，系数只需是随机数即可。可以考虑使用`rand.Int`生成适当范围内的随机数。

// 4. **插值函数的实现**:
//    - `CalLagrangian`中的实现可能不正确。计算权重时，应该先计算`xj - xi`的模逆，再与`xj`相乘。此外，整个权重计算应该在模`q`下进行。

// ### 结论

// 您的代码提供了一个基于椭圆曲线参数的秘密共享方案的实现框架，但在实际部署前需要仔细检查和测试，特别是在数学运算和安全性处理方面。优化计算过程和增强错误处理能力将是提高代码质量和安全性的关键。
