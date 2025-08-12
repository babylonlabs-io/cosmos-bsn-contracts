package e2e

import (
	"encoding/json"
	"testing"

	sdkmath "cosmossdk.io/math"
	wasmibctesting "github.com/CosmWasm/wasmd/tests/wasmibctesting"
	"github.com/babylonlabs-io/babylon-sdk/demo/app"
	appparams "github.com/babylonlabs-io/babylon-sdk/demo/app/params"
	bbnsdktypes "github.com/babylonlabs-io/babylon-sdk/x/babylon/types"
	btclctypes "github.com/babylonlabs-io/babylon/v3/x/btclightclient/types"
	"github.com/babylonlabs-io/cosmos-bsn-contracts/e2e/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	ibctesting "github.com/cosmos/ibc-go/v10/testing"
	"github.com/stretchr/testify/suite"
)

// In the Test function, we create and run the suite
func TestBabylonSDKTestSuite(t *testing.T) {
	suite.Run(t, new(BabylonSDKTestSuite))
}

// Define the test suite and include the s.Suite struct
type BabylonSDKTestSuite struct {
	suite.Suite

	// provider/consumer and their metadata
	Coordinator      *ibctesting.Coordinator
	ProviderChain    *wasmibctesting.WasmTestChain
	ConsumerChain    *wasmibctesting.WasmTestChain
	ConsumerApp      *app.ConsumerApp
	IbcPath          *ibctesting.Path
	ProviderDenom    string
	ConsumerDenom    string
	MyProvChainActor string

	// clients side information
	ProviderCli      *types.TestProviderClient
	ConsumerCli      *types.TestConsumerClient
	ConsumerContract *types.ConsumerContract

	// temporary variables
	initialHeader *btclctypes.BTCHeaderInfo
}

// SetupSuite runs once before the suite's tests are run
func (s *BabylonSDKTestSuite) SetupSuite() {
	// overwrite init messages in Babylon
	appparams.SetAddressPrefixes()

	// set up coordinator and chains
	t := s.T()
	coord := types.NewCoordinator(t, 2)
	provChain := coord.GetChain(ibctesting.GetChainID(1))
	consChain := coord.GetChain(ibctesting.GetChainID(2))

	s.Coordinator = coord
	s.ConsumerChain = wasmibctesting.NewWasmTestChain(consChain)
	s.ProviderChain = wasmibctesting.NewWasmTestChain(provChain)
	s.ConsumerApp = consChain.App.(*app.ConsumerApp)
	s.IbcPath = ibctesting.NewPath(consChain, provChain)
	s.ProviderDenom = sdk.DefaultBondDenom
	s.ConsumerDenom = sdk.DefaultBondDenom
	s.MyProvChainActor = provChain.SenderAccount.GetAddress().String()

	s.initialHeader = types.GenInitialBTCHeaderInfo()
}

func (s *BabylonSDKTestSuite) Test1ContractDeployment() {
	// consumer client
	consumerCli := types.NewConsumerClient(s.T(), s.ConsumerChain)
	// setup contracts on consumer (now just fetches addresses)
	consumerContracts, err := consumerCli.BootstrapContracts()
	s.NoError(err)
	// provider client
	providerCli := types.NewProviderClient(s.T(), s.ProviderChain)

	s.NotEmpty(consumerCli.Chain.ChainID)
	s.NotEmpty(providerCli.Chain.ChainID)
	s.NotEmpty(consumerContracts.Babylon)
	s.NotEmpty(consumerContracts.BTCLightClient)
	s.NotEmpty(consumerContracts.BTCStaking)
	s.NotEmpty(consumerContracts.BTCFinality)

	s.ProviderCli = providerCli
	s.ConsumerCli = consumerCli
	s.ConsumerContract = consumerContracts

	// assert the contract addresses are updated in params
	ctx := s.ConsumerChain.GetContext()
	s.Equal(s.ConsumerContract.Babylon.String(), s.ConsumerApp.BabylonKeeper.GetBSNContracts(ctx).BabylonContract)
	s.Equal(s.ConsumerContract.BTCLightClient.String(), s.ConsumerApp.BabylonKeeper.GetBSNContracts(ctx).BtcLightClientContract)
	s.Equal(s.ConsumerContract.BTCStaking.String(), s.ConsumerApp.BabylonKeeper.GetBSNContracts(ctx).BtcStakingContract)
	s.Equal(s.ConsumerContract.BTCFinality.String(), s.ConsumerApp.BabylonKeeper.GetBSNContracts(ctx).BtcFinalityContract)

	// query admins
	admin := s.ConsumerCli.GetSender().String()
	adminRespStaking, err := s.ConsumerCli.Query(s.ConsumerContract.BTCStaking, types.Query{"admin": {}})
	s.NoError(err)
	s.Equal(adminRespStaking["admin"], admin)
	adminRespFinality, err := s.ConsumerCli.Query(s.ConsumerContract.BTCFinality, types.Query{"admin": {}})
	s.NoError(err)
	s.Equal(adminRespFinality["admin"], admin)
	adminRespLightClient, err := s.ConsumerCli.Query(s.ConsumerContract.BTCLightClient, types.Query{"admin": {}})
	s.NoError(err)
	s.Equal(adminRespLightClient["admin"], admin)

	// query the config of BTC light client contract
	configResp, err := s.ConsumerCli.Query(s.ConsumerContract.BTCLightClient, types.Query{"config": {}})
	s.NoError(err)
	s.NotEmpty(configResp)
	s.Equal(configResp["babylon_contract_address"], s.ConsumerContract.Babylon.String())
	// TODO: why this is float64 even though it's u32 in rust
	s.Equal(configResp["btc_confirmation_depth"], float64(1))
	s.Equal(configResp["checkpoint_finalization_timeout"], float64(2))
}

func (s *BabylonSDKTestSuite) Test2InsertBTCHeaders() {
	// generate headers
	headers, headersMsg := types.GenBTCHeadersMsg(nil)
	headersMsgBytes, err := json.Marshal(headersMsg)
	s.NoError(err)
	// send headers to the BTCLightClient contract. This is to ensure that the contract is
	// indexing BTC headers correctly.
	res, err := s.ConsumerCli.Exec(s.ConsumerContract.BTCLightClient, headersMsgBytes)
	s.T().Logf("err: %v", err)
	s.NoError(err, res)

	// query the base header
	baseHeader, err := s.ConsumerCli.Query(s.ConsumerContract.BTCLightClient, types.Query{"btc_base_header": {}})
	s.NoError(err)
	s.NotEmpty(baseHeader)
	s.T().Logf("baseHeader: %v", baseHeader)

	// query the tip header
	tipHeader, err := s.ConsumerCli.Query(s.ConsumerContract.BTCLightClient, types.Query{"btc_tip_header": {}})
	s.NoError(err)
	s.NotEmpty(tipHeader)
	s.T().Logf("tipHeader: %v", tipHeader)

	// insert more headers
	_, headersMsg2 := types.GenBTCHeadersMsg(headers[len(headers)-1])
	headersMsgBytes2, err := json.Marshal(headersMsg2)
	s.NoError(err)
	res, err = s.ConsumerCli.Exec(s.ConsumerContract.BTCLightClient, headersMsgBytes2)
	s.NoError(err, res)

	// query the tip header again
	tipHeader2, err := s.ConsumerCli.Query(s.ConsumerContract.BTCLightClient, types.Query{"btc_tip_header": {}})
	s.NoError(err)
	s.NotEmpty(tipHeader2)
	s.T().Logf("tipHeader2: %v", tipHeader2)
}

func (s *BabylonSDKTestSuite) Test3MockConsumerFpDelegation() {
	testMsg := types.GenExecMessage(s.T())
	msgBytes, err := json.Marshal(testMsg)
	s.NoError(err)

	// send msg to BTC staking contract via admin account
	_, err = s.ConsumerCli.Exec(s.ConsumerContract.BTCStaking, msgBytes)
	s.NoError(err)

	// ensure the finality provider is on consumer chain
	consumerFps, err := s.ConsumerCli.Query(s.ConsumerContract.BTCStaking, types.Query{"finality_providers": {}})
	s.NoError(err)
	s.NotEmpty(consumerFps)

	// ensure delegations are on consumer chain
	consumerDels, err := s.ConsumerCli.Query(s.ConsumerContract.BTCStaking, types.Query{"delegations": {}})
	s.NoError(err)
	s.NotEmpty(consumerDels)

	// BTC staking won't be activated because there is no timestamped pub rand
	_, err = s.ConsumerCli.Query(s.ConsumerContract.BTCFinality, types.Query{"activated_height": {}})
	s.Error(err)

	// TODO: find a way to timestamp pub rand to activate BTC staking
	// this requires a new handler for adding BTC timestamps to the Babylon contract
	// but extra security measures are needed to prevent abuse
}

func (s *BabylonSDKTestSuite) Test4BeginBlock() {
	var err error

	portion, _ := sdkmath.LegacyNewDecFromStr("0.1")
	err = s.ConsumerApp.BabylonKeeper.SetParams(s.ConsumerChain.GetContext(), bbnsdktypes.Params{
		MaxGasBeginBlocker: 200_000,
		MaxGasEndBlocker:   200_000,
		BtcStakingPortion:  portion,
	})
	s.NoError(err)

	err = s.ConsumerApp.BabylonKeeper.BeginBlocker(s.ConsumerChain.GetContext())
	s.NoError(err)
}

func (s *BabylonSDKTestSuite) Test4EndBlock() {
	_, err := s.ConsumerApp.BabylonKeeper.EndBlocker(s.ConsumerChain.GetContext())
	s.NoError(err)
}

func (s *BabylonSDKTestSuite) Test5NextBlock() {
	// get current height
	height := s.ConsumerChain.GetContext().BlockHeight()

	// the block should not be indexed because the BTC staking is not activated
	_, err := s.ConsumerCli.Query(s.ConsumerContract.BTCFinality, types.Query{
		"block": {
			"height": uint64(height),
		},
	})
	s.Error(err)
}

// TearDownSuite runs once after all the suite's tests have been run
func (s *BabylonSDKTestSuite) TearDownSuite() {
	// Cleanup code here
}
