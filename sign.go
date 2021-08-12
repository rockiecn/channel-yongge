package role

import (
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gogo/protobuf/proto"
	"github.com/memoio/go-mefs/contracts"
	"github.com/memoio/go-mefs/contracts/upKeeping"
	id "github.com/memoio/go-mefs/crypto/identity"
	mpb "github.com/memoio/go-mefs/pb"
	"github.com/memoio/go-mefs/utils"
	"github.com/memoio/go-mefs/utils/address"
	"golang.org/x/crypto/sha3"
)

//SignForChannel user sends a private key signature to the provider
func SignForChannel(channelID, hexKey string, value *big.Int) (sig []byte, err error) {
	channelAddr, err := address.GetAddressFromID(channelID)
	if err != nil {
		return nil, err
	}

	//(channelAddress, value)的哈希值
	valueNew := common.LeftPadBytes(value.Bytes(), 32)
	hash := crypto.Keccak256(channelAddr.Bytes(), valueNew) //32Byte

	//私钥格式转换
	skECDSA, err := id.ECDSAStringToSk(hexKey)
	if err != nil {
		return sig, err
	}

	//私钥对上述哈希值签名
	sig, err = crypto.Sign(hash, skECDSA)
	if err != nil {
		return sig, err
	}

	pubKey, err := id.GetCompressPubByte(hexKey)
	if err != nil {
		utils.MLogger.Error("Get public key fail: ", err)
		return nil, err
	}

	message := &mpb.ChannelSign{
		Sig:       sig,
		PubKey:    pubKey,
		Value:     value.Bytes(),
		ChannelID: channelID,
	}

	mes, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}

	return mes, nil
}

//VerifyChannelSign provider used to verify user's signature for channel-contract
func VerifyChannelSign(cSign *mpb.ChannelSign) (verify bool) {
	channelAddr, err := address.GetAddressFromID(cSign.GetChannelID())
	if err != nil {
		return false
	}

	//(channelAddress, value)的哈希值
	valueNew := common.LeftPadBytes(cSign.GetValue(), 32)
	hash := crypto.Keccak256(channelAddr.Bytes(), valueNew)

	//验证签名
	return crypto.VerifySignature(cSign.GetPubKey(), hash, cSign.GetSig()[:64])
}
