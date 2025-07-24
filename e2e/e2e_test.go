package e2e

import (
	"encoding/json"
	"testing"

	wasmibctesting "github.com/CosmWasm/wasmd/tests/wasmibctesting"
	"github.com/babylonlabs-io/babylon-sdk/demo/app"
	appparams "github.com/babylonlabs-io/babylon-sdk/demo/app/params"
	btclctypes "github.com/babylonlabs-io/babylon/v3/x/btclightclient/types"
	"github.com/babylonlabs-io/cosmos-bsn-contracts/e2e/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	ibctesting "github.com/cosmos/ibc-go/v10/testing"
	"github.com/stretchr/testify/suite"
)

var testMsg types.ExecuteMessage

// In the Test function, we create and run the suite
func TestBabylonSDKTestSuite(t *testing.T) {
	suite.Run(t, new(BabylonSDKTestSuite))
}

// Define the test suite and include the s.Suite struct
type BabylonSDKTestSuite struct {
	suite.Suite

	// provider/consumer and their metadata
	Coordinator      *ibctesting.Coordinator
	ConsumerChain    *wasmibctesting.WasmTestChain
	ProviderChain    *wasmibctesting.WasmTestChain
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
	consumerContracts, err := consumerCli.BootstrapContracts(s.initialHeader)
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
	adminRespStaking, err := s.ConsumerCli.Query(s.ConsumerContract.BTCStaking, types.Query{"admin": {}})
	s.NoError(err)
	s.Equal(adminRespStaking["admin"], s.ConsumerCli.GetSender().String())
	adminRespFinality, err := s.ConsumerCli.Query(s.ConsumerContract.BTCFinality, types.Query{"admin": {}})
	s.NoError(err)
	s.Equal(adminRespFinality["admin"], s.ConsumerCli.GetSender().String())
}

func (s *BabylonSDKTestSuite) Test2InsertBTCHeaders() {
	// generate headers
	headers, headersMsg := types.GenBTCHeadersMsg(s.initialHeader)
	headersMsgBytes, err := json.Marshal(headersMsg)
	s.NoError(err)
	// send headers to the BTCLightClient contract. This is to ensure that the contract is
	// indexing BTC headers correctly.
	res, err := s.ConsumerCli.Exec(s.ConsumerContract.BTCLightClient, headersMsgBytes)
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
	testMsg = types.GenExecMessage()
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

	// ensure the BTC staking is activated
	resp, err := s.ConsumerCli.Query(s.ConsumerContract.BTCStaking, types.Query{"activated_height": {}})
	s.NoError(err)
	parsedActivatedHeight := resp["height"].(float64)
	currentHeight := s.ConsumerChain.GetContext().BlockHeight()
	s.Equal(uint64(parsedActivatedHeight), uint64(currentHeight))
}

func (s *BabylonSDKTestSuite) Test4BeginBlock() {
	err := s.ConsumerApp.BabylonKeeper.BeginBlocker(s.ConsumerChain.GetContext())
	s.NoError(err)
}

func (s *BabylonSDKTestSuite) Test4EndBlock() {
	_, err := s.ConsumerApp.BabylonKeeper.EndBlocker(s.ConsumerChain.GetContext())
	s.NoError(err)
}

func (s *BabylonSDKTestSuite) Test5NextBlock() {
	// get current height
	height := s.ConsumerChain.GetContext().BlockHeight()

	// check the current block indexing status
	resp, err := s.ConsumerCli.Query(s.ConsumerContract.BTCFinality, types.Query{
		"block": {
			"height": uint64(height),
		},
	})
	s.NoError(err)

	// Check that the block exists but may not be fully indexed (app_hash is empty)
	s.NotNil(resp)
	s.Equal(float64(height), resp["height"])
	appHash, ok := resp["app_hash"].([]interface{})
	s.True(ok, "app_hash should be present")
	s.Empty(appHash, "app_hash should be empty before NextBlock")

	// this triggers BeginBlock and EndBlock
	s.ConsumerChain.NextBlock()

	// ensure the current block is fully indexed (app_hash should be populated)
	resp, err = s.ConsumerCli.Query(s.ConsumerContract.BTCFinality, types.Query{
		"block": {
			"height": uint64(height),
		},
	})
	s.NoError(err)

	// Verify the block is fully indexed with app_hash populated
	s.NotNil(resp)
	s.Equal(float64(height), resp["height"])

	// Check that app_hash is populated (indicating full indexing)
	appHash, ok = resp["app_hash"].([]interface{})
	s.True(ok, "app_hash should be present")
	s.NotEmpty(appHash, "app_hash should be populated after NextBlock")
}

// TearDownSuite runs once after all the suite's tests have been run
func (s *BabylonSDKTestSuite) TearDownSuite() {
	// Cleanup code here
}
