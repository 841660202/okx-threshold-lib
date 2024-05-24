package reshare

import (
	"crypto/elliptic"
	"fmt"
	"log"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/key/dkg"
)

func TestRefresh4(t *testing.T) {
	// curve := edwards.Edwards()
	curve := secp256k1.S256()
	p1Data, p2Data, p3Data, p4Data := KeyGen4(curve)

	// 假设p1Data, p2Data, p3Data, p4Data已经被初始化
	// 记录密钥刷新前的私钥份额
	log.Println("Before Refresh:")
	log.Printf("Participant 1 ShareI: %v\n", p1Data.ShareI)
	log.Printf("Participant 2 ShareI: %v\n", p2Data.ShareI)
	log.Printf("Participant 3 ShareI: %v\n", p3Data.ShareI)
	log.Printf("Participant 4 ShareI: %v\n", p4Data.ShareI)

	// Reset private key share by 2, 4 // 要被重置的
	devoteList := [2]int{1, 2}
	fmt.Println()
	fmt.Println("👀一不一致")
	fmt.Println()
	// fmt.Println("p1Data.PublicKey", p1Data.PublicKey)
	// fmt.Println("p2Data.PublicKey", p2Data.PublicKey)
	// fmt.Println("p3Data.PublicKey", p3Data.PublicKey)
	// fmt.Println("p4Data.PublicKey", p4Data.PublicKey)
	fmt.Println()
	fmt.Println()
	refresh1 := NewRefresh(1, 4, devoteList, p1Data.ShareI /*非空都要参与重置*/, p1Data.PublicKey)
	refresh2 := NewRefresh(2, 4, devoteList, p2Data.ShareI /*非空都要参与重置*/, p2Data.PublicKey)
	refresh3 := NewRefresh(3, 4, devoteList, nil /*非空都要参与重置*/, p3Data.PublicKey)
	refresh4 := NewRefresh(4, 4, devoteList, nil /*非空都要参与重置*/, p4Data.PublicKey)
	// 结构体含有字段输出
	log.Printf("Refresh 1 ui: %v\n", refresh1.ui)
	log.Printf("Refresh 2 ui: %v\n", refresh2.ui)
	log.Printf("Refresh 3 ui: %v\n", refresh3.ui)
	log.Printf("Refresh 4 ui: %v\n", refresh4.ui)

	// fmt.Println("刷新顶呱刮")
	// fmt.Println("刷新顶呱刮")
	// 第一轮
	msgs1_1, _ := refresh1.DKGStep1() //2，3，4
	msgs2_1, _ := refresh2.DKGStep1() //1，3，4
	msgs3_1, _ := refresh3.DKGStep1() //1，2，4
	msgs4_1, _ := refresh4.DKGStep1() //1，2，3
	// fmt.Println("刷新顶呱刮")
	// fmt.Println("刷新顶呱刮")
	// fmt.Println("刷新顶呱刮")
	// 第二轮消息输入
	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1], msgs4_1[1]} //2->1,3->1,4->1
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2], msgs4_1[2]} //1->2,3->2,4->2
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3], msgs4_1[3]} //1->3,2->3,4->3
	msgs4_2_in := []*tss.Message{msgs1_1[4], msgs2_1[4], msgs3_1[4]} //1->4,2->4,3->4
	// 生成第二轮消息结果
	msgs1_2, _ := refresh1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := refresh2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := refresh3.DKGStep2(msgs3_2_in)
	msgs4_2, _ := refresh4.DKGStep2(msgs4_2_in)
	// 第三轮消息输入
	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1], msgs4_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2], msgs4_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3], msgs4_2[3]}
	msgs4_3_in := []*tss.Message{msgs1_2[4], msgs2_2[4], msgs3_2[4]}
	// 生成私钥片段和公钥
	p1SaveData, _ := refresh1.DKGStep3(msgs1_3_in)
	p2SaveData, _ := refresh2.DKGStep3(msgs2_3_in)
	p3SaveData, _ := refresh3.DKGStep3(msgs3_3_in)
	p4SaveData, _ := refresh4.DKGStep3(msgs4_3_in)

	// fmt.Println()
	// fmt.Println()
	// fmt.Println("refresh1-p1SaveData.PublickKey", p1SaveData.PublicKey)
	// fmt.Println()
	// fmt.Println("refresh2-p2SaveData.PublickKey", p2SaveData.PublicKey)
	// fmt.Println()
	// fmt.Println("refresh3-p3SaveData.PublickKey", p3SaveData.PublicKey)
	// fmt.Println()
	// fmt.Println("refresh4-p4SaveData.PublickKey", p4SaveData.PublicKey)
	// fmt.Println()

	// 记录密钥刷新后的私钥份额
	log.Println("After Refresh:")
	log.Printf("Participant 1 ShareI: %v\n", p1SaveData.ShareI)
	log.Printf("Participant 2 ShareI: %v\n", p2SaveData.ShareI)
	log.Printf("Participant 3 ShareI: %v\n", p3SaveData.ShareI)
	log.Printf("Participant 4 ShareI: %v\n", p4SaveData.ShareI)

	// 对比前后的私钥份额
	log.Println("Comparison:")
	log.Printf("Participant 1 ShareI changed: %v\n", compareShares(p1Data.ShareI, p1SaveData.ShareI))
	log.Printf("Participant 2 ShareI changed: %v\n", compareShares(p2Data.ShareI, p2SaveData.ShareI))
	log.Printf("Participant 3 ShareI changed: %v\n", compareShares(p3Data.ShareI, p3SaveData.ShareI))
	log.Printf("Participant 4 ShareI changed: %v\n", compareShares(p4Data.ShareI, p4SaveData.ShareI))

}

// compareShares 比较两个私钥份额是否相同
func compareShares(share1, share2 interface{}) bool {
	return fmt.Sprintf("%v", share1) == fmt.Sprintf("%v", share2)
}

func KeyGen4(curve elliptic.Curve) (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data) {
	setUp1 := dkg.NewSetUp(1, 4, curve)
	setUp2 := dkg.NewSetUp(2, 4, curve)
	setUp3 := dkg.NewSetUp(3, 4, curve)
	setUp4 := dkg.NewSetUp(4, 4, curve)

	msgs1_1, _ := setUp1.DKGStep1()
	msgs2_1, _ := setUp2.DKGStep1()
	msgs3_1, _ := setUp3.DKGStep1()
	msgs4_1, _ := setUp4.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1], msgs4_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2], msgs4_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3], msgs4_1[3]}
	msgs4_2_in := []*tss.Message{msgs1_1[4], msgs2_1[4], msgs3_1[4]}

	msgs1_2, _ := setUp1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := setUp2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := setUp3.DKGStep2(msgs3_2_in)
	msgs4_2, _ := setUp4.DKGStep2(msgs4_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1], msgs4_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2], msgs4_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3], msgs4_2[3]}
	msgs4_3_in := []*tss.Message{msgs1_2[4], msgs2_2[4], msgs3_2[4]}

	p1SaveData, _ := setUp1.DKGStep3(msgs1_3_in)
	p2SaveData, _ := setUp2.DKGStep3(msgs2_3_in)
	p3SaveData, _ := setUp3.DKGStep3(msgs3_3_in)
	p4SaveData, _ := setUp4.DKGStep3(msgs4_3_in)
	// fmt.Printf("refresh1-setUp1: %+v\n\n", setUp1)
	// fmt.Printf("refresh2-setUp2: %+v\n\n", setUp2)
	// fmt.Printf("refresh3-setUp3: %+v\n\n", setUp3)
	// fmt.Printf("refresh4-setUp4: %+v\n\n", setUp4)

	// fmt.Println("setUp1", p1SaveData, p1SaveData.PublicKey)
	// fmt.Println("setUp2", p2SaveData, p2SaveData.PublicKey)
	// fmt.Println("setUp3", p3SaveData, p3SaveData.PublicKey)
	// fmt.Println("setUp4", p4SaveData, p4SaveData.PublicKey)
	return p1SaveData, p2SaveData, p3SaveData, p4SaveData
}
