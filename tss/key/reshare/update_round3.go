package reshare

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/vss"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/key/dkg"
)

// DKGStep3 return new key share information except chaincode
// DKGStep3 返回新的密钥共享信息，除了链码
func (info *RefreshInfo) DKGStep3(msgs []*tss.Message) (*tss.KeyStep3Data, error) {
	log.Printf("RefreshInfo DKGStep3: ID=%d, ShareI=%v\n", info.DeviceNumber, info.shareI)

	// 检查当前轮次是否为第三轮
	if info.RoundNumber != 3 {
		return nil, fmt.Errorf("round error")
	}
	// 检查消息数量是否正确
	if len(msgs) != (info.Total - 1) {
		return nil, fmt.Errorf("messages number error")
	}

	// 获取椭圆曲线
	curve := info.curve
	feldman, err := vss.NewFeldman(info.Threshold, info.Total, curve)
	if err != nil {
		return nil, err
	}

	verifiers := make(map[int][]*curves.ECPoint, len(msgs))
	verifiers[info.DeviceNumber] = info.verifiers

	/*----------------获取当前参与者共享的秘密-------*/
	xi := info.secretShares[info.DeviceNumber-1]
	for _, msg := range msgs {
		// 检查消息是否发送到当前设备
		if msg.To != info.DeviceNumber {
			return nil, fmt.Errorf("message sending error")
		}
		var content tss.KeyStep2Data
		// 反序列化消息数据
		err := json.Unmarshal([]byte(msg.Data), &content)
		if err != nil {
			return nil, err
		}
		// 创建哈希承诺
		hashCommit := commitment.HashCommitment{}
		hashCommit.C = info.commitmentMap[msg.From]
		hashCommit.Msg = *content.Witness
		ok, D := hashCommit.Open()
		if !ok {
			return nil, fmt.Errorf("commitment DeCommit fail")
		}

		// 反序列化验证者
		verifiers[msg.From], err = dkg.UnmarshalVerifiers(curve, D, info.Threshold)

		// 验证秘密份额
		if ok, err := feldman.Verify(content.Share, verifiers[msg.From]); !ok {
			if err != nil {
				return nil, err
			} else {
				return nil, fmt.Errorf("invalid share for participant")
			}
		}

		/*----------------更新秘密份额-------*/
		xi.Y = new(big.Int).Add(xi.Y, content.Share.Y)

		// 验证 Schnorr 证明
		ujPoint := verifiers[msg.From][0]

		// 过滤 0*G
		if ujPoint.X.Cmp(big.NewInt(0)) == 0 || ujPoint.Y.Cmp(big.NewInt(0)) == 0 {
			continue
		}
		point, err := curves.NewECPoint(curve, ujPoint.X, ujPoint.Y)
		if err != nil {
			return nil, err
		}
		// 验证零知识证明
		verify := schnorr.Verify(content.Proof, point)
		if !verify {
			return nil, fmt.Errorf("schnorr verify fail")
		}
	}

	/* ============================== 计算新的公共密钥 =================*/
	v := make([]*curves.ECPoint, info.Threshold)
	for j := 0; j < info.Threshold; j++ {
		v[j] = curves.ScalarToPoint(curve, big.NewInt(0))

		for _, verifier := range verifiers {
			if !verifier[j].IsOnCurve() {
				continue
			}
			v[j], err = v[j].Add(verifier[j])
			if err != nil {
				return nil, err
			}
		}
	}

	/* ============================== 计算每个参与方的公共密钥 =================*/
	sharePubKeyMap := make(map[int]*curves.ECPoint, info.Threshold)
	for k := 1; k <= info.Total; k++ {
		Yi := v[0]
		tmp := big.NewInt(1)
		for i := 1; i < info.Threshold; i++ {
			tmp = tmp.Mul(tmp, big.NewInt(int64(k))) // temp 是通过乘法，逐步累积k^i次方
			point := v[i]                            // 取出多项式的第  项系数a i
			// 标量乘法
			point = point.ScalarMult(tmp)
			Yi, err = Yi.Add(point)
		}
		sharePubKeyMap[k] = Yi
	}

	/* ============================== 验证秘密份额的公共密钥是否正确 =================*/
	xiG /*公共密钥*/ := curves.ScalarToPoint(curve, xi.Y /*秘密份额*/) // 转成椭圆曲线上的点
	if !sharePubKeyMap[info.DeviceNumber].Equals(xiG) {        // 与预先计算好的密钥份额比较
		return nil, fmt.Errorf("public key calculation error")
	}

	/* ============================== 验证新的公共密钥是否与之前的公共密钥相同 =================*/
	if !v[0].Equals(info.publicKey) {
		return nil, fmt.Errorf("public key recalculation error")
	}

	// 更新信息
	info.shareI = xi.Y
	info.publicKey = v[0]

	// 创建并返回新的密钥步骤数据
	content := &tss.KeyStep3Data{
		Id:             info.DeviceNumber,
		ShareI:         info.shareI,
		PublicKey:      info.publicKey,
		SharePubKeyMap: sharePubKeyMap,
	}
	return content, nil
}
