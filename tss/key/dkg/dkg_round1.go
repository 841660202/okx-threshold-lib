package dkg

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/vss"
	"github.com/okx/threshold-lib/tss"
)

// DKGStep1 p2p send verifiers commitment
func (info *SetupInfo) DKGStep1() (map[int]*tss.Message, error) {
	if info.RoundNumber != 1 {
		return nil, fmt.Errorf("round error")
	}
	// random generate ui, private key = sum(ui)
	// 随机生成ui，私钥 = sum(ui)
	// ui 是一个缩写

	// 在分布式密钥生成（DKG）的上下文中，`ui` 可能是 "user index" 或 "user input" 的缩写，
	// 但更常见的可能是 "user individual" 或 "unique identifier" 的简称。在这种情况下，每个参与者（user）生成一个独特的随机数（`ui`），
	// 作为他们对最终密钥的个人贡献。这个随机数对于每个参与者是唯一的，因此称为 "individual" 或 "unique"。

	// 然而，`ui` 的具体含义可能因上下文和实现的不同而有所变化。在没有特定文档明确解释的情况下，
	// `ui` 通常被理解为与每个参与者相关的一个唯一的或个人的数值。在密码学和密钥生成协议中，确保每个参与者的贡献是唯一和随机的，是非常重要的安全措施。
	ui := crypto.RandomNum(info.curve.Params().N)

	// feldman
	feldman, err := vss.NewFeldman(info.Threshold, info.Total, info.curve)
	if err != nil {
		return nil, err
	}
	// verifiers [a0*G, a1*G, ...], shares [fi(1), fi(2), ...]
	verifiers, shares, err := feldman.Evaluate(ui)
	if err != nil {
		return nil, err
	}
	// each one generates a chaincode, actual chaincode = sum(chaincode)
	chaincode := crypto.RandomNum(info.curve.Params().N)

	// compute verifiers and chaincode commitment
	var input []*big.Int
	input = append(input, chaincode)
	for i := 0; i < len(verifiers); i++ {
		input = append(input, verifiers[i].X, verifiers[i].Y)
	}
	hashCommitment := commitment.NewCommitment(input...)

	info.ui = ui
	info.deC = &hashCommitment.Msg
	info.secretShares = shares
	info.verifiers = verifiers
	info.chaincode = chaincode
	info.RoundNumber = 2

	out := make(map[int]*tss.Message, info.Total-1)
	for _, id := range info.Ids() {
		if id == info.DeviceNumber {
			continue
		}
		// each message send p2p, not broadcast
		// step1: verifiers commitment
		content := tss.KeyStep1Data{C: &hashCommitment.C}
		bytes, err := json.Marshal(content)
		if err != nil {
			return nil, err
		}
		message := &tss.Message{
			From: info.DeviceNumber,
			To:   id,
			Data: string(bytes),
		}
		out[id] = message
	}
	return out, nil
}

// 在密码学中，`Feldman`是指Feldman的可验证秘密共享（Verifiable Secret Sharing, VSS）方案的一种实现。这个方案允许一个秘密被分成多个份额，分发给多个参与者，同时确保这些份额可以被验证以保证其正确性和完整性。在您提到的代码片段中：

// ```go
// verifiers, shares, err := feldman.Evaluate(ui)
// ```

// 这里的 `Feldman.Evaluate` 函数可能是在执行以下操作：

// 1. **入参：**
//    - `ui`：这通常是参与者的私有贡献或份额，用于生成秘密的一部分。在Feldman VSS中，这可能是用于生成多项式的一个系数。

// 2. **结果：**
//    - `verifiers`：验证者或验证密钥。在Feldman VSS中，这些通常是从生成的多项式中计算出的点，用于后续验证各份额的有效性。
//    - `shares`：秘密的份额，这些份额被分发给其他参与者。每个份额应该是多项式在不同点的评估结果。
//    - `err`：如果在执行过程中发生错误，它将捕获并返回该错误。

// 在Feldman VSS中，多项式的系数是随机选择的，其中最高次项的系数通常是秘密本身或与秘密相关的值。多项式的其他系数（如`ui`）用于帮助构造这个多项式，并确保秘密可以安全地被分享和重构。

// 这个方案的关键特点是它允许参与者验证他们接收到的份额是否正确，而不需要知道整个秘密。这是通过检查他们的份额是否满足预先公布的验证者（或验证点）来实现的。如果份额满足这些验证点，则可以认为份额是正确的。

// 总之，`Feldman.Evaluate` 函数在这里可能是在用参与者的输入`ui`来生成可验证的秘密份额和相应的验证数据，以便在分发秘密份额时，每个接收者都能独立验证其份额的正确性。
