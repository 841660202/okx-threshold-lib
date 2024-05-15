package reshare

import (
	"crypto/elliptic"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/key/dkg"

	"github.com/sirupsen/logrus"
)

// TestRefresh测试用例用于测试密钥刷新过程。密钥刷新是阈值签名方案中的一个重要环节，它允许参与者在不改变公钥的情况下更新他们的私钥份额
// - **步骤**：
//   1. 使用`KeyGen`生成初始密钥。
//   2. 初始化`NewRefresh`对象，指定哪些参与者需要刷新他们的密钥份额。
//   3. 类似于密钥生成，刷新过程通过多轮消息交换完成。每一轮（`DKGStep1`, `DKGStep2`, `DKGStep3`）都涉及到生成消息、交换消息和处理消息。
//   4. 最终，每个参与者都会得到新的私钥份额，而公钥保持不变。

var log = logrus.New()

func TestRefresh(t *testing.T) {
	// 设置输出为彩色
	log.SetFormatter(&logrus.TextFormatter{
		ForceColors:      true,
		FullTimestamp:    false,
		DisableTimestamp: true,
	})

	// 1. 使用`KeyGen`生成初始密钥。
	// curve := edwards.Edwards()
	curve := secp256k1.S256()
	p1Data, p2Data, p3Data := KeyGen(curve)
	// Reset private key share by 1, 3
	devoteList := [2]int{1, 3}

	// 2. 初始化`NewRefresh`对象，指定哪些参与者需要刷新他们的密钥份额。
	refresh1 := NewRefresh(1, 3, devoteList, p1Data.ShareI, p1Data.PublicKey)
	refresh2 := NewRefresh(2, 3, devoteList, nil, p2Data.PublicKey)
	refresh3 := NewRefresh(3, 3, devoteList, p3Data.ShareI, p3Data.PublicKey)

	msgs1_1, _ := refresh1.DKGStep1()
	msgs2_1, _ := refresh2.DKGStep1()
	msgs3_1, _ := refresh3.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}

	msgs1_2, _ := refresh1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := refresh2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := refresh3.DKGStep2(msgs3_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}

	// 最终，每个参与者都会得到新的私钥份额，而公钥保持不变。
	p1SaveData, _ := refresh1.DKGStep3(msgs1_3_in)
	p2SaveData, _ := refresh2.DKGStep3(msgs2_3_in)
	p3SaveData, _ := refresh3.DKGStep3(msgs3_3_in)

	log.Info("----------refresh 1 2 3------------------")

	log.Info("\n refresh1", p1SaveData, "\n\n p1SaveData.PublicKey: ", p1SaveData.PublicKey)
	log.Info("\n refresh2", p2SaveData, "\n\n p2SaveData.PublicKey: ", p2SaveData.PublicKey)
	log.Info("\n refresh3", p3SaveData, "\n\n p3SaveData.PublicKey: ", p3SaveData.PublicKey)

}

// KeyGen函数的目的是生成初始的密钥分发数据

// - **步骤**：
//  1. 使用`dkg.NewSetUp`初始化三个参与者的密钥生成环境。
//  2. 通过`DKGStep1`生成第一轮的消息并交换。
//  3. 使用收到的消息进行`DKGStep2`，进一步交换信息。
//  4. 最后通过`DKGStep3`完成密钥生成，每个参与者得到自己的私钥份额和共有的公钥。
func KeyGen(curve elliptic.Curve) (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data) {
	// 1.
	setUp1 := dkg.NewSetUp(1, 3, curve)
	setUp2 := dkg.NewSetUp(2, 3, curve)
	setUp3 := dkg.NewSetUp(3, 3, curve)
	// 通过`DKGStep1`生成第一轮的消息并交换。
	msgs1_1, _ := setUp1.DKGStep1()
	msgs2_1, _ := setUp2.DKGStep1()
	msgs3_1, _ := setUp3.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}
	// 使用收到的消息进行`DKGStep2`，进一步交换信息。
	msgs1_2, _ := setUp1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := setUp2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := setUp3.DKGStep2(msgs3_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}
	// 最后通过`DKGStep3`完成密钥生成
	p1SaveData, _ := setUp1.DKGStep3(msgs1_3_in)
	p2SaveData, _ := setUp2.DKGStep3(msgs2_3_in)
	p3SaveData, _ := setUp3.DKGStep3(msgs3_3_in)
	log.Info("----------setUp 1 2 3------------------")
	log.Info("\n setUp1: ", p1SaveData, "\n\n PublicKey: ", p1SaveData.PublicKey)
	log.Info("\n setUp2: ", p2SaveData, "\n\n PublicKey: ", p2SaveData.PublicKey)
	log.Info("\n setUp3: ", p3SaveData, "\n\n PublicKey: ", p3SaveData.PublicKey)
	return p1SaveData, p2SaveData, p3SaveData
}

// 这段代码中包含了两个主要的功能部分，分别是`KeyGen`函数和`TestRefresh`测试用例。它们都是基于阈值签名方案的密钥生成和密钥刷新过程的实现和测试。下面分别对这两部分进行解析：

// ### KeyGen 函数
// `KeyGen`函数的目的是生成初始的密钥分发数据，这是多方计算中的一个重要步骤。在阈值签名方案中，密钥生成（Distributed Key Generation, DKG）允许多个参与者共同生成一个公私钥对，其中私钥被分割为多个份额，每个参与者持有一份。

// - **步骤**：
//   1. 使用`dkg.NewSetUp`初始化三个参与者的密钥生成环境。
//   2. 通过`DKGStep1`生成第一轮的消息并交换。
//   3. 使用收到的消息进行`DKGStep2`，进一步交换信息。
//   4. 最后通过`DKGStep3`完成密钥生成，每个参与者得到自己的私钥份额和共有的公钥。

// 这个函数在测试密钥刷新逻辑前提供了必要的初始密钥设置。

// ### TestRefresh 测试用例
// `TestRefresh`测试用例用于测试密钥刷新过程。密钥刷新是阈值签名方案中的一个重要环节，它允许参与者在不改变公钥的情况下更新他们的私钥份额。这对于提高密钥的安全性和实现密钥的周期性更新非常重要。

// - **步骤**：
//   1. 使用`KeyGen`生成初始密钥。
//   2. 初始化`NewRefresh`对象，指定哪些参与者需要刷新他们的密钥份额。
//   3. 类似于密钥生成，刷新过程通过多轮消息交换完成。每一轮（`DKGStep1`, `DKGStep2`, `DKGStep3`）都涉及到生成消息、交换消息和处理消息。
//   4. 最终，每个参与者都会得到新的私钥份额，而公钥保持不变。

// 这个测试用例的目的是验证密钥刷新机制的正确性，确保在整个过程中公钥保持不变，同时每个参与者的私钥份额得到正确的更新。

// ### 总结
// 这两部分代码共同构成了一个完整的阈值签名方案的密钥管理测试，从密钥的初始生成到后续的刷新更新，都涉及到复杂的多方计算和密钥协议。测试这些功能的正确性对于确保系统的安全性和功能性至关重要。
