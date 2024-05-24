package reshare

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/vss"
	"github.com/okx/threshold-lib/tss"
)

// DKGStep1 初始化分布式密钥生成（DKG）协议的第一步
func (info *RefreshInfo) DKGStep1() (map[int]*tss.Message, error) {
	log.Printf("RefreshInfo DKGStep1: ID=%d, ShareI=%v\n", info.DeviceNumber, info.shareI)
	// 检查当前轮次是否为第一轮
	if info.RoundNumber != 1 {
		return nil, fmt.Errorf("round error")
	}

	// 初始化 Feldman VSS
	feldman, err := vss.NewFeldman(info.Threshold, info.Total, info.curve)
	if err != nil {
		return nil, err
	}

	// 评估当前设备的秘密份额 ui，生成验证者和份额
	verifiers, shares, err := feldman.Evaluate(info.ui)
	if err != nil {
		return nil, err
	}

	// 计算验证者的承诺（不包括链码）
	var input []*big.Int
	for i := 0; i < len(verifiers); i++ {
		input = append(input, verifiers[i].X, verifiers[i].Y)
	}
	hashCommitment := commitment.NewCommitment(input...)

	// 存储承诺信息和秘密份额
	// ui不变
	info.deC = &hashCommitment.Msg
	info.secretShares = shares
	info.verifiers = verifiers
	// chaincode不变
	info.RoundNumber = 2

	out := make(map[int]*tss.Message, info.Total-1) //  p2p 发送给其他参与者的消息
	for _, id := range info.Ids() {
		if id == info.DeviceNumber {
			continue
		}
		// 创建消息内容，包括承诺 C
		content := tss.KeyStep1Data{C: &hashCommitment.C}
		bytes, err := json.Marshal(content)
		if err != nil {
			return nil, err
		}
		// 创建消息
		message := &tss.Message{
			From: info.DeviceNumber,
			To:   id,
			Data: string(bytes),
		}
		// 将消息添加到输出 map 中
		out[id] = message
	}
	return out, nil
}
