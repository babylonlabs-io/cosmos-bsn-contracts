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

func NewBTCLightClientInitMsg(admin string, network string, k int, w int) []byte {
	data := map[string]interface{}{
		"admin":                           admin,
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
	k int,
	w int,
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
		"btc_confirmation_depth":          k,
		"checkpoint_finalization_timeout": w,
		"btc_light_client_code_id":        btcLightClientCodeID,
		"btc_staking_code_id":             btcStakingCodeID,
		"btc_finality_code_id":            btcFinalityCodeID,
		"admin":                           admin,
		"consumer_name":                   consumerName,
		"consumer_description":            consumerDescription,
		"ics20_channel_id":                ics20ChannelID,
		"destination_module":              "btcstaking",
	}

	if len(btcLightClientInitMsg) > 0 {
		data["btc_light_client_msg"] = base64.StdEncoding.EncodeToString(btcLightClientInitMsg)
	}
	if len(btcStakingInitMsg) > 0 {
		data["btc_staking_msg"] = base64.StdEncoding.EncodeToString(btcStakingInitMsg)
	}
	if len(btcFinalityInitMsg) > 0 {
		data["btc_finality_msg"] = base64.StdEncoding.EncodeToString(btcFinalityInitMsg)
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	return jsonBytes
}

type NewFinalityProvider struct {
	Description *FinalityProviderDescription `json:"description,omitempty"`
	Commission  string                       `json:"commission"`
	Addr        string                       `json:"addr,omitempty"`
	BTCPKHex    string                       `json:"btc_pk_hex"`
	Pop         *ProofOfPossessionBtc        `json:"pop,omitempty"`
	ConsumerID  string                       `json:"consumer_id"`
}

type FinalityProviderDescription struct {
	Moniker         string `json:"moniker"`
	Identity        string `json:"identity"`
	Website         string `json:"website"`
	SecurityContact string `json:"security_contact"`
	Details         string `json:"details"`
}

type ProofOfPossessionBtc struct {
	BTCSigType int32  `json:"btc_sig_type"`
	BTCSig     string `json:"btc_sig"`
}

type CovenantAdaptorSignatures struct {
	CovPK       string   `json:"cov_pk"`
	AdaptorSigs []string `json:"adaptor_sigs"`
}

type SignatureInfo struct {
	PK  string `json:"pk"`
	Sig string `json:"sig"`
}

type BtcUndelegationInfo struct {
	UnbondingTx           string                      `json:"unbonding_tx"`
	DelegatorUnbondingSig string                      `json:"delegator_unbonding_sig"`
	CovenantUnbondingSigs []SignatureInfo             `json:"covenant_unbonding_sig_list"`
	SlashingTx            string                      `json:"slashing_tx"`
	DelegatorSlashingSig  string                      `json:"delegator_slashing_sig"`
	CovenantSlashingSigs  []CovenantAdaptorSignatures `json:"covenant_slashing_sigs"`
}

type ActiveBtcDelegation struct {
	StakerAddr           string                      `json:"staker_addr"`
	BTCPkHex             string                      `json:"btc_pk_hex"`
	FpBtcPkList          []string                    `json:"fp_btc_pk_list"`
	StartHeight          uint32                      `json:"start_height"`
	EndHeight            uint32                      `json:"end_height"`
	TotalSat             uint64                      `json:"total_sat"`
	StakingTx            string                      `json:"staking_tx"`
	SlashingTx           string                      `json:"slashing_tx"`
	DelegatorSlashingSig string                      `json:"delegator_slashing_sig"`
	CovenantSigs         []CovenantAdaptorSignatures `json:"covenant_sigs"`
	StakingOutputIdx     uint32                      `json:"staking_output_idx"`
	UnbondingTime        uint32                      `json:"unbonding_time"`
	UndelegationInfo     BtcUndelegationInfo         `json:"undelegation_info"`
	ParamsVersion        uint32                      `json:"params_version"`
}

type SlashedBtcDelegation struct {
	// Define fields as needed
}

type UnbondedBtcDelegation struct {
	StakingTxHash string `json:"staking_tx_hash"`
}

type BabylonExecuteMsg struct {
	BtcHeaders BTCHeadersMsg `json:"btc_headers"`
}

type BTCHeadersMsg struct {
	Headers     []*BtcHeader `json:"headers"`
	FirstWork   *string      `json:"first_work,omitempty"`
	FirstHeight *uint32      `json:"first_height,omitempty"`
}

type ExecuteMessage struct {
	BtcStaking BtcStaking `json:"btc_staking"`
}

type BtcStaking struct {
	NewFP       []NewFinalityProvider   `json:"new_fp"`
	ActiveDel   []ActiveBtcDelegation   `json:"active_del"`
	UnbondedDel []UnbondedBtcDelegation `json:"unbonded_del"`
}

type MigrateMsg struct {
}

func NewMigrateMsg() []byte {
	msg := MigrateMsg{}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		panic(err)
	}
	return msgBytes
}

func NewUnbondedDelMessage(stakingTxHash string) *ExecuteMessage {
	msg := &ExecuteMessage{
		BtcStaking: BtcStaking{
			NewFP:     []NewFinalityProvider{},
			ActiveDel: []ActiveBtcDelegation{},
			UnbondedDel: []UnbondedBtcDelegation{
				{
					StakingTxHash: stakingTxHash,
				},
			},
		},
	}
	return msg
}
