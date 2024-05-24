package dkg

import (
	"encoding/json"
	"fmt"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/tss"
)

// DKGStep2 receive first step message and execute second step
func (info *SetupInfo) DKGStep2(msgs []*tss.Message) (map[int]*tss.Message, error) {
	if info.RoundNumber != 2 {
		return nil, fmt.Errorf("round error")
	}
	if len(msgs) != (info.Total - 1) {
		return nil, fmt.Errorf("messages number error")
	}
	info.commitmentMap = make(map[int]commitment.Commitment, len(msgs))
	for _, msg := range msgs {
		if msg.To != info.DeviceNumber {
			return nil, fmt.Errorf("message sending error")
		}
		var content tss.KeyStep1Data
		err := json.Unmarshal([]byte(msg.Data), &content)
		if err != nil {
			return nil, err
		}
		info.commitmentMap[msg.From] = *content.C // &hashCommitment.C
	}

	// compute zkSchnorr prove for ui
	uiG := curves.ScalarToPoint(info.curve, info.ui)
	proof, err := schnorr.Prove(info.ui /*随机数*/, uiG /*公钥*/) // 计算零知识证明
	if err != nil {
		return nil, err
	}
	info.RoundNumber = 3

	out := make(map[int]*tss.Message, info.Total-1)
	// to ： 接受人(参与者)的id
	for _, id := range info.Ids() {
		if id == info.DeviceNumber {
			continue
		}
		// step2: commitment data、secretShares and schnorr proof for ui（私钥份额）
		content := tss.KeyStep2Data{
			Witness: info.deC, // 随机数，密钥份额slice
			Share:   info.secretShares[id-1],
			Proof:   proof,
		}
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
	return out, nil // out 当前参与者：收集发送给其他参与者的消息（消息的内容：承诺的信息，，密钥分享slice = step1 的 feldman.Evaluate(ui), 零知识证明）
}

// DKGStep2 函数处理第一轮的消息，计算必要的证明，并生成第二轮的消息。生成的 out 映射包含了要发送给其他参与者的消息，每个消息都包含以下内容：

// Witness：承诺数据。
// Share：秘密分享。
// Proof：零知识证明。
// 这些消息将用于第二轮的分布式密钥生成协议。
