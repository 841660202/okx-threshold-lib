package dkg

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/tss"
)

// 分布式密钥生成（Distributed Key Generation, DKG）
// 在阈值签名方案中，密钥生成（Distributed Key Generation, DKG）允许多个参与者共同生成一个公私钥对，
// 其中私钥被分割为多个份额，每个参与者持有一份
// {2,3}-threshold
func TestKeyGen(t *testing.T) {
	curve := secp256k1.S256() // edwards.Edwards()
	setUp1 := NewSetUp(1, 3, curve)
	setUp2 := NewSetUp(2, 3, curve)
	setUp3 := NewSetUp(3, 3, curve)
	// DKGStep1
	msgs1_1, _ := setUp1.DKGStep1()
	msgs2_1, _ := setUp2.DKGStep1()
	msgs3_1, _ := setUp3.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}
	// DKGStep2
	msgs1_2, _ := setUp1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := setUp2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := setUp3.DKGStep2(msgs3_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}
	// DKGStep3
	p1SaveData, _ := setUp1.DKGStep3(msgs1_3_in)
	p2SaveData, _ := setUp2.DKGStep3(msgs2_3_in)
	p3SaveData, _ := setUp3.DKGStep3(msgs3_3_in)

	fmt.Println("setUp1", p1SaveData, p1SaveData.PublicKey)
	fmt.Println("setUp2", p2SaveData, p2SaveData.PublicKey)
	fmt.Println("setUp3", p3SaveData, p3SaveData.PublicKey)

	// 将结构体实例转换为JSON格式
	jsonData, err := json.MarshalIndent(p1SaveData, "", "    ")
	if err != nil {

		fmt.Println("json.Marshal failed, err:", err)
	}
	fmt.Println("setUp1 json")
	// 打印JSON字符串
	fmt.Println(string(jsonData))
	// 将结构体实例转换为JSON格式
	jsonData2, err := json.MarshalIndent(p2SaveData, "", "    ")
	if err != nil {

		fmt.Println("json.Marshal failed, err:", err)
	}

	fmt.Println("setUp2 json")
	// 打印JSON字符串
	fmt.Println(string(jsonData2))
	// 将结构体实例转换为JSON格式
	jsonData3, err := json.MarshalIndent(p3SaveData, "", "    ")
	if err != nil {

		fmt.Println("json.Marshal failed, err:", err)
	}

	fmt.Println("setUp3 json")
	// 打印JSON字符串
	fmt.Println(string(jsonData3))

}

// {2,4}-threshold
func TestKeyGen2_4(t *testing.T) {
	curve := secp256k1.S256() // edwards.Edwards()
	setUp1 := NewSetUp(1, 4, curve)
	setUp2 := NewSetUp(2, 4, curve)
	setUp3 := NewSetUp(3, 4, curve)
	setUp4 := NewSetUp(4, 4, curve)
	// DKGStep1
	msgs1_1, _ := setUp1.DKGStep1()
	msgs2_1, _ := setUp2.DKGStep1()
	msgs3_1, _ := setUp3.DKGStep1()
	msgs4_1, _ := setUp4.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1], msgs4_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2], msgs4_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3], msgs4_1[3]}
	msgs4_2_in := []*tss.Message{msgs1_1[4], msgs2_1[4], msgs3_1[4]}
	// DKGStep2
	msgs1_2, _ := setUp1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := setUp2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := setUp3.DKGStep2(msgs3_2_in)
	msgs4_2, _ := setUp4.DKGStep2(msgs4_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1], msgs4_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2], msgs4_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3], msgs4_2[3]}
	msgs4_3_in := []*tss.Message{msgs1_2[4], msgs2_2[4], msgs3_2[4]}
	// DKGStep3
	p1SaveData, err := setUp1.DKGStep3(msgs1_3_in)
	if err != nil {
		panic(fmt.Sprintf("Error on step 3 party 1: %s", err))
	}
	p2SaveData, err := setUp2.DKGStep3(msgs2_3_in)
	if err != nil {
		panic(fmt.Sprintf("Error on step 3 party 2: %s", err))
	}
	p3SaveData, err := setUp3.DKGStep3(msgs3_3_in)
	if err != nil {
		panic(fmt.Sprintf("Error on step 3 party 3: %s", err))
	}
	p4SaveData, err := setUp4.DKGStep3(msgs4_3_in)
	if err != nil {
		panic(fmt.Sprintf("Error on step 3 party 4: %s", err))
	}

	fmt.Println("setUp1", p1SaveData, p1SaveData.PublicKey)
	fmt.Println("setUp2", p2SaveData, p2SaveData.PublicKey)
	fmt.Println("setUp3", p3SaveData, p3SaveData.PublicKey)
	fmt.Println("setUp4", p4SaveData, p4SaveData.PublicKey)
}
