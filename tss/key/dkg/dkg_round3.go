package dkg

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/vss"
	"github.com/okx/threshold-lib/tss"
)

// DKGStep3 receive second step message and execute dkg finish
// return key share information
func (info *SetupInfo) DKGStep3(msgs []*tss.Message) (*tss.KeyStep3Data, error) {
	if info.RoundNumber != 3 {
		return nil, fmt.Errorf("round error")
	}
	if len(msgs) != (info.Total - 1) {
		return nil, fmt.Errorf("messages number error")
	}

	curve := info.curve
	feldman, err := vss.NewFeldman(info.Threshold, info.Total, curve)
	if err != nil {
		return nil, err
	}
	/*---------------------------------------------------------------------------------------------------*/
	verifiers := make(map[int][]*curves.ECPoint, len(msgs))
	verifiers[info.DeviceNumber] = info.verifiers
	chaincode := info.chaincode
	xi := info.secretShares[info.DeviceNumber-1] // 取私钥份额
	for _, msg := range msgs {
		if msg.To != info.DeviceNumber {
			return nil, fmt.Errorf("message sending error")
		}
		var data tss.KeyStep2Data
		err := json.Unmarshal([]byte(msg.Data), &data) // 上一步将content tss.KeyStep2Data 放到了msg.Data， 这步是取出来
		if err != nil {
			return nil, err
		}
		// check verifiers commitment
		hashCommit := commitment.HashCommitment{}
		hashCommit.C = info.commitmentMap[msg.From]
		hashCommit.Msg = *data.Witness
		ok, D := hashCommit.Open()
		if !ok {
			return nil, fmt.Errorf("commitment DeCommit fail")
		}
		//  actual chaincode = sum(chaincode)
		chaincode = new(big.Int).Add(chaincode, D[0]) // 通过累加承诺值的随机数来累加链码

		verifiers[msg.From], err = UnmarshalVerifiers(curve, D[1:], info.Threshold) // 将验证者取出来

		if err != nil {
			return nil, err
		}

		// feldman verify
		if ok, err := feldman.Verify(data.Share /*上一步的密钥份额*/, verifiers[msg.From] /*伴生验证者*/); !ok {
			if err != nil {
				return nil, err
			} else {
				return nil, fmt.Errorf("invalid share for participant  ")
			}
		}
		xi.Y = new(big.Int).Add(xi.Y, data.Share.Y) // 将所有的累加在一起生成新的密钥份额

		ujPoint := verifiers[msg.From][0] // 为什么取0，
		// [0] 表示取出该参与者的第一个验证者点， 在许多 DKG 协议中，参与者会发布多个验证者点（对应于多项式的每一项）。
		// 使用第一个验证者点进行 Schnorr 证明验证，可以确保常数项的承诺是有效的。

		point, err := curves.NewECPoint(curve, ujPoint.X, ujPoint.Y)
		if err != nil {
			return nil, err
		}
		// schnorr verify for ui
		verify := schnorr.Verify(data.Proof, point)
		if !verify {
			return nil, fmt.Errorf("schnorr verify fail")
		}
	}

	v := make([]*curves.ECPoint, info.Threshold)
	for j := 0; j < info.Threshold; j++ {
		v[j] = curves.ScalarToPoint(curve, big.NewInt(0))

		for _, verifier := range verifiers {
			v[j], err = v[j].Add(verifier[j])
			if err != nil {
				return nil, err
			}
		}
	}
	/*---------------------------------------------------------------------------------------------------*/
	// 每个参与者验证自己计算的公共密钥是否正确。
	sharePubKeyMap := make(map[int]*curves.ECPoint, info.Threshold)
	// 每个参与者的公共密钥份额计算Yk
	for k := 1; k <= info.Total; k++ {
		Yi := v[0]
		tmp := big.NewInt(1)
		for i := 1; i < info.Threshold; i++ {
			tmp = tmp.Mul(tmp, big.NewInt(int64(k)))
			point := v[i]
			point = point.ScalarMult(tmp)
			Yi, err = Yi.Add(point)
			if err != nil {
				return nil, err
			}
		}
		sharePubKeyMap[k] = Yi
	}
	// check share publicKey
	xiG /*公钥份额*/ := curves.ScalarToPoint(curve, xi.Y /*私钥份额*/)
	if !sharePubKeyMap[info.DeviceNumber].Equals(xiG) {
		return nil, fmt.Errorf("public key calculation error")
	}

	/*---------------------------------------------------------------------------------------------------*/

	info.shareI = xi.Y
	info.publicKey = v[0]

	content := &tss.KeyStep3Data{
		Id:             info.DeviceNumber,
		ShareI:         info.shareI,
		PublicKey:      info.publicKey,
		ChainCode:      hex.EncodeToString(chaincode.Bytes()),
		SharePubKeyMap: sharePubKeyMap,
	}
	return content, nil
}

func UnmarshalVerifiers(curve elliptic.Curve, msg []*big.Int, threshold int) ([]*curves.ECPoint, error) {
	if len(msg) != (threshold * 2) {
		return nil, fmt.Errorf("invalid number of verifier shares")
	}
	verifiers := make([]*curves.ECPoint, threshold)
	for k := 0; k < threshold; k++ {
		verifiers[k] = &curves.ECPoint{
			Curve: curve,
			X:     msg[2*k],
			Y:     msg[2*k+1],
		}
	}
	return verifiers, nil
}
