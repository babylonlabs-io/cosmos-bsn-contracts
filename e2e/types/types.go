package types

import (
	"encoding/base64"
	"encoding/json"

	"github.com/btcsuite/btcd/wire"
)

type BtcHeader struct {
	Version       int32  `json:"version"`
	PrevBlockhash string `json:"prev_blockhash"`
	MerkleRoot    string `json:"merkle_root"`
	Time          int64  `json:"time"`
	Bits          uint32 `json:"bits"`
	Nonce         uint32 `json:"nonce"`
}

func NewBtcHeader(header *wire.BlockHeader) *BtcHeader {
	return &BtcHeader{
		Version:       header.Version,
		PrevBlockhash: header.PrevBlock.String(),
		MerkleRoot:    header.MerkleRoot.String(),
		Time:          header.Timestamp.Unix(),
		Bits:          header.Bits,
		Nonce:         header.Nonce,
	}
}

func NewBTCLightClientInitMsg(network string, k int, w int) []byte {
	data := map[string]interface{}{
		"network":                         network,
		"btc_confirmation_depth":          k,
		"checkpoint_finalization_timeout": w,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	return jsonBytes
}

func NewBTCStakingInitMsg(admin string) []byte {
	data := map[string]interface{}{
		"admin": admin,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	return jsonBytes
}

func NewBTCFinalityInitMsg(admin string) []byte {
	data := map[string]interface{}{
		"admin": admin,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	return jsonBytes
}

func NewBabylonInitMsg(
	network string,
	babylonTag string,
	k int,
	w int,
	notifyCosmosZone bool,
	btcLightClientCodeID uint64,
	btcLightClientInitMsg []byte,
	btcStakingCodeID uint64,
	btcStakingInitMsg []byte,
	btcFinalityCodeID uint64,
	btcFinalityInitMsg []byte,
	admin string,
	consumerName string,
	consumerDescription string,
	ics20ChannelID string,
) []byte {
	data := map[string]interface{}{
		"network":                         network,
		"babylon_tag":                     babylonTag,
		"btc_confirmation_depth":          k,
		"checkpoint_finalization_timeout": w,
		"notify_cosmos_zone":              notifyCosmosZone,
		"btc_light_client_code_id":        btcLightClientCodeID,
		"btc_light_client_msg":            base64.StdEncoding.EncodeToString(btcLightClientInitMsg),
		"btc_staking_code_id":             btcStakingCodeID,
		"btc_staking_msg":                 base64.StdEncoding.EncodeToString(btcStakingInitMsg),
		"btc_finality_code_id":            btcFinalityCodeID,
		"btc_finality_msg":                base64.StdEncoding.EncodeToString(btcFinalityInitMsg),
		"admin":                           admin,
		"consumer_name":                   consumerName,
		"consumer_description":            consumerDescription,
		"ics20_channel_id":                ics20ChannelID,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	return jsonBytes
}
