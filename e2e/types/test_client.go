package types

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	ibctesting "github.com/CosmWasm/wasmd/tests/wasmibctesting"
	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	"github.com/stretchr/testify/require"

	"github.com/babylonlabs-io/babylon-sdk/demo/app"
	babylontypes "github.com/babylonlabs-io/babylon-sdk/x/babylon/types"
)

const (
	TEST_DATA_DIR                  = "../artifacts"
	BABYLON_CONTRACT_PATH          = TEST_DATA_DIR + "/babylon_contract.wasm"
	BTC_LIGHT_CLIENT_CONTRACT_PATH = TEST_DATA_DIR + "/btc_light_client.wasm"
	BTC_STAKING_CONTRACT_PATH      = TEST_DATA_DIR + "/btc_staking.wasm"
	BTC_FINALITY_CONTRACT_PATH     = TEST_DATA_DIR + "/btc_finality.wasm"
)

// Query is a query type used in tests only
type Query map[string]map[string]any

// QueryResponse is a response type used in tests only
type QueryResponse map[string]any

// To can be used to navigate through the map structure
func (q QueryResponse) To(path ...string) QueryResponse {
	r, ok := q[path[0]]
	if !ok {
		panic(fmt.Sprintf("key %q does not exist", path[0]))
	}
	var x QueryResponse = r.(map[string]any)
	if len(path) == 1 {
		return x
	}
	return x.To(path[1:]...)
}

func (q QueryResponse) Array(key string) []QueryResponse {
	val, ok := q[key]
	if !ok {
		panic(fmt.Sprintf("key %q does not exist", key))
	}
	sl := val.([]any)
	result := make([]QueryResponse, len(sl))
	for i, v := range sl {
		result[i] = v.(map[string]any)
	}
	return result
}

func Querier(t *testing.T, chain *ibctesting.WasmTestChain) func(contract string, query Query) (QueryResponse, error) {
	return func(contract string, query Query) (QueryResponse, error) {
		qRsp := make(map[string]any)
		err := chain.SmartQuery(contract, query, &qRsp)
		if err != nil {
			return nil, err
		}
		return qRsp, nil
	}
}

type TestProviderClient struct {
	t     *testing.T
	Chain *ibctesting.WasmTestChain
}

func NewProviderClient(t *testing.T, chain *ibctesting.WasmTestChain) *TestProviderClient {
	return &TestProviderClient{t: t, Chain: chain}
}

func (p *TestProviderClient) Exec(contract sdk.AccAddress, payload []byte, funds ...sdk.Coin) (*abci.ExecTxResult, error) {
	rsp, err := p.Chain.SendMsgs(&wasmtypes.MsgExecuteContract{
		Sender:   p.Chain.SenderAccount.GetAddress().String(),
		Contract: contract.String(),
		Msg:      payload,
		Funds:    funds,
	})
	return rsp, err
}

type TestConsumerClient struct {
	t         *testing.T
	Chain     *ibctesting.WasmTestChain
	Contracts ConsumerContract
	App       *app.ConsumerApp
}

func NewConsumerClient(t *testing.T, chain *ibctesting.WasmTestChain) *TestConsumerClient {
	return &TestConsumerClient{t: t, Chain: chain, App: chain.App.(*app.ConsumerApp)}
}

type ConsumerContract struct {
	Babylon        sdk.AccAddress
	BTCLightClient sdk.AccAddress
	BTCStaking     sdk.AccAddress
	BTCFinality    sdk.AccAddress
}

func (p *TestConsumerClient) GetSender() sdk.AccAddress {
	return p.Chain.SenderAccount.GetAddress()
}

func (p *TestConsumerClient) BootstrapContracts() (*ConsumerContract, error) {
	// Query the Babylon module for contract addresses
	contracts := p.App.BabylonKeeper.GetBSNContracts(p.Chain.GetContext())
	if contracts == nil || !contracts.IsSet() {
		// If contracts are not set, deploy them
		return p.deployContracts()
	}

	babylonAddr, err := sdk.AccAddressFromBech32(contracts.BabylonContract)
	if err != nil {
		return nil, fmt.Errorf("invalid Babylon contract address: %w", err)
	}
	btcLightClientAddr, err := sdk.AccAddressFromBech32(contracts.BtcLightClientContract)
	if err != nil {
		return nil, fmt.Errorf("invalid BTC Light Client contract address: %w", err)
	}
	btcStakingAddr, err := sdk.AccAddressFromBech32(contracts.BtcStakingContract)
	if err != nil {
		return nil, fmt.Errorf("invalid BTC Staking contract address: %w", err)
	}
	btcFinalityAddr, err := sdk.AccAddressFromBech32(contracts.BtcFinalityContract)
	if err != nil {
		return nil, fmt.Errorf("invalid BTC Finality contract address: %w", err)
	}

	r := ConsumerContract{
		Babylon:        babylonAddr,
		BTCLightClient: btcLightClientAddr,
		BTCStaking:     btcStakingAddr,
		BTCFinality:    btcFinalityAddr,
	}
	p.Contracts = r
	return &r, nil
}

func (p *TestConsumerClient) deployContracts() (*ConsumerContract, error) {
	ctx := p.Chain.GetContext()
	wasmKeeper := p.App.WasmKeeper
	wasmMsgServer := wasmkeeper.NewMsgServerImpl(&wasmKeeper)

	// Load contract WASM files
	babylonWasm, err := os.ReadFile(BABYLON_CONTRACT_PATH)
	if err != nil {
		return nil, fmt.Errorf("failed to read babylon contract: %w", err)
	}
	btcLightClientWasm, err := os.ReadFile(BTC_LIGHT_CLIENT_CONTRACT_PATH)
	if err != nil {
		return nil, fmt.Errorf("failed to read btc light client contract: %w", err)
	}
	btcStakingWasm, err := os.ReadFile(BTC_STAKING_CONTRACT_PATH)
	if err != nil {
		return nil, fmt.Errorf("failed to read btc staking contract: %w", err)
	}
	btcFinalityWasm, err := os.ReadFile(BTC_FINALITY_CONTRACT_PATH)
	if err != nil {
		return nil, fmt.Errorf("failed to read btc finality contract: %w", err)
	}

	// Store contracts
	babylonResp, err := wasmMsgServer.StoreCode(ctx, &wasmtypes.MsgStoreCode{
		Sender:       p.Chain.SenderAccount.GetAddress().String(),
		WASMByteCode: babylonWasm,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store babylon contract: %w", err)
	}
	babylonCodeID := babylonResp.CodeID

	btcLightClientResp, err := wasmMsgServer.StoreCode(ctx, &wasmtypes.MsgStoreCode{
		Sender:       p.Chain.SenderAccount.GetAddress().String(),
		WASMByteCode: btcLightClientWasm,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store btc light client contract: %w", err)
	}
	btcLightClientCodeID := btcLightClientResp.CodeID

	btcStakingResp, err := wasmMsgServer.StoreCode(ctx, &wasmtypes.MsgStoreCode{
		Sender:       p.Chain.SenderAccount.GetAddress().String(),
		WASMByteCode: btcStakingWasm,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store btc staking contract: %w", err)
	}
	btcStakingCodeID := btcStakingResp.CodeID

	btcFinalityResp, err := wasmMsgServer.StoreCode(ctx, &wasmtypes.MsgStoreCode{
		Sender:       p.Chain.SenderAccount.GetAddress().String(),
		WASMByteCode: btcFinalityWasm,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store btc finality contract: %w", err)
	}
	btcFinalityCodeID := btcFinalityResp.CodeID

	// Prepare init messages for the other contracts
	admin := p.Chain.SenderAccount.GetAddress().String()
	network := "regtest"
	kValue := 1
	wValue := 2
	babylonTag := "01020304"
	consumerName := "test-consumer"
	consumerDescription := "test-consumer-description"
	ics20ChannelID := "channel-1"

	// Create init messages for other contracts
	btcLightClientInitMsg := NewBTCLightClientInitMsg(admin, network, kValue, wValue)
	btcStakingInitMsg := NewBTCStakingInitMsg(admin)
	btcFinalityInitMsg := NewBTCFinalityInitMsg(admin)

	// Build the Babylon contract instantiation message
	babylonInitMsg := NewBabylonInitMsg(
		network,
		babylonTag,
		kValue,
		wValue,
		false,
		btcLightClientCodeID,
		btcLightClientInitMsg,
		btcStakingCodeID,
		btcStakingInitMsg,
		btcFinalityCodeID,
		btcFinalityInitMsg,
		admin,
		consumerName,
		consumerDescription,
		ics20ChannelID,
	)

	// Instantiate the Babylon contract
	babylonInstResp, err := wasmMsgServer.InstantiateContract(ctx, &wasmtypes.MsgInstantiateContract{
		Sender: admin,
		Admin:  admin,
		CodeID: babylonCodeID,
		Label:  "babylon",
		Msg:    babylonInitMsg,
		Funds:  nil,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate babylon contract: %w", err)
	}
	babylonAddr := babylonInstResp.Address

	// Query the Babylon contract's Config {} to get all contract addresses
	// The Babylon contract needs time to instantiate the other contracts internally
	configQuery := []byte(`{"config":{}}`)
	babylonAccAddr, err := sdk.AccAddressFromBech32(babylonAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid babylon address: %w", err)
	}

	// Query the Babylon contract's Config {} to get all contract addresses
	var configRes []byte
	configRes, err = wasmKeeper.QuerySmart(ctx, babylonAccAddr, configQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query babylon contract config: %w", err)
	}

	var config struct {
		BTCLightClient string `json:"btc_light_client"`
		BTCStaking     string `json:"btc_staking"`
		BTCFinality    string `json:"btc_finality"`
	}
	err = json.Unmarshal(configRes, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config response: %w", err)
	}

	// Set BSN contracts in the Babylon module
	contracts := &babylontypes.BSNContracts{
		BabylonContract:        babylonAddr,
		BtcLightClientContract: config.BTCLightClient, // First element is the contract address
		BtcStakingContract:     config.BTCStaking,
		BtcFinalityContract:    config.BTCFinality,
	}

	err = p.App.BabylonKeeper.SetBSNContracts(ctx, contracts)
	if err != nil {
		return nil, fmt.Errorf("failed to set BSN contracts: %w", err)
	}

	// Verify that the contracts exist in the wasm keeper
	btcLightClientAccAddr, err := sdk.AccAddressFromBech32(config.BTCLightClient)
	if err != nil {
		return nil, fmt.Errorf("invalid btc light client address: %w", err)
	}
	btcStakingAccAddr, err := sdk.AccAddressFromBech32(config.BTCStaking)
	if err != nil {
		return nil, fmt.Errorf("invalid btc staking address: %w", err)
	}
	btcFinalityAccAddr, err := sdk.AccAddressFromBech32(config.BTCFinality)
	if err != nil {
		return nil, fmt.Errorf("invalid btc finality address: %w", err)
	}

	// Convert addresses to AccAddress
	r := ConsumerContract{
		Babylon:        babylonAccAddr,
		BTCLightClient: btcLightClientAccAddr,
		BTCStaking:     btcStakingAccAddr,
		BTCFinality:    btcFinalityAccAddr,
	}
	p.Contracts = r
	return &r, nil
}

func (p *TestConsumerClient) Exec(contract sdk.AccAddress, payload []byte, funds ...sdk.Coin) (*abci.ExecTxResult, error) {
	rsp, err := p.Chain.SendMsgs(&wasmtypes.MsgExecuteContract{
		Sender:   p.GetSender().String(),
		Contract: contract.String(),
		Msg:      payload,
		Funds:    funds,
	})
	return rsp, err
}

func (p *TestConsumerClient) Query(contractAddr sdk.AccAddress, query Query) (QueryResponse, error) {
	// Use the wasm keeper directly instead of the test chain's SmartQuery
	// This ensures we're using the same context and query mechanism
	ctx := p.Chain.GetContext()
	wasmKeeper := p.App.WasmKeeper

	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	response, err := wasmKeeper.QuerySmart(ctx, contractAddr, queryBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to query contract: %w", err)
	}

	var result QueryResponse
	err = json.Unmarshal(response, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return result, nil
}

func submitGovProposal(t *testing.T, chain *ibctesting.WasmTestChain, msgs ...sdk.Msg) uint64 {
	// get gov module parameters
	chainApp := chain.App.(*app.ConsumerApp)
	govParams, err := chainApp.GovKeeper.Params.Get(chain.GetContext())
	require.NoError(t, err)

	// construct proposal
	govMsg, err := govv1.NewMsgSubmitProposal(msgs, govParams.MinDeposit, chain.SenderAccount.GetAddress().String(), "", "my title", "my summary", false)
	require.NoError(t, err)

	// submit proposal
	_, err = chain.SendMsgs(govMsg)
	require.NoError(t, err)

	// get next proposal ID
	proposalID, err := chainApp.GovKeeper.ProposalID.Peek(chain.GetContext())
	require.NoError(t, err)

	return proposalID - 1
}

func voteAndPassGovProposal(t *testing.T, chain *ibctesting.WasmTestChain, proposalID uint64) {
	// get gov module parameters
	chainApp := chain.App.(*app.ConsumerApp)
	govParams, err := chainApp.GovKeeper.Params.Get(chain.GetContext())
	require.NoError(t, err)

	// construct and submit vote
	vote := govv1.NewMsgVote(chain.SenderAccount.GetAddress(), proposalID, govv1.OptionYes, "testing")
	_, err = chain.SendMsgs(vote)
	require.NoError(t, err)

	// pass voting period
	coord := chain.Coordinator
	coord.IncrementTimeBy(*govParams.VotingPeriod)
	coord.CommitBlock(chain.TestChain)

	// ensure proposal is passed
	proposal, err := chainApp.GovKeeper.Proposals.Get(chain.GetContext(), proposalID)
	require.NoError(t, err)
	require.Equal(t, proposal.Status, govv1.ProposalStatus_PROPOSAL_STATUS_PASSED)
}
