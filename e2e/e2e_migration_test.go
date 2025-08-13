package e2e

import (
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

// In the Test function, we create and run the suite
func TestContractMigrationSuite(t *testing.T) {
	suite.Run(t, new(ContractMigrationSuite))
}

// Define the test suite and include the s.Suite struct
type ContractMigrationSuite struct {
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
func (s *ContractMigrationSuite) SetupSuite() {
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

func (s *ContractMigrationSuite) Test1ContractDeployment() {
	// consumer client
	consumerCli := types.NewConsumerClient(s.T(), s.ConsumerChain)
	// setup old contracts on consumer
	consumerContracts, err := consumerCli.BootstrapContracts(
		types.OLD_BABYLON_CONTRACT_PATH,
		types.OLD_BTC_LIGHT_CLIENT_CONTRACT_PATH,
		types.OLD_BTC_STAKING_CONTRACT_PATH,
		types.OLD_BTC_FINALITY_CONTRACT_PATH,
		true, // pin codes
	)
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

}

func (s *ContractMigrationSuite) Test2ContractMigration() {
	ctx := s.ConsumerChain.GetContext()

	// assert there is only 1 code ID for each contract
	history := s.ConsumerCli.App.WasmKeeper.GetContractHistory(ctx, s.ConsumerContract.Babylon)
	s.Len(history, 1)
	history = s.ConsumerCli.App.WasmKeeper.GetContractHistory(ctx, s.ConsumerContract.BTCLightClient)
	s.Len(history, 1)
	history = s.ConsumerCli.App.WasmKeeper.GetContractHistory(ctx, s.ConsumerContract.BTCStaking)
	s.Len(history, 1)
	history = s.ConsumerCli.App.WasmKeeper.GetContractHistory(ctx, s.ConsumerContract.BTCFinality)
	s.Len(history, 1)

	// migrate the contracts
	err := s.ConsumerCli.MigrateContracts(
		types.BABYLON_CONTRACT_PATH,
		types.BTC_LIGHT_CLIENT_CONTRACT_PATH,
		types.BTC_STAKING_CONTRACT_PATH,
		types.BTC_FINALITY_CONTRACT_PATH,
	)
	s.NoError(err)

	// ensure the code ID is updated
	history = s.ConsumerCli.App.WasmKeeper.GetContractHistory(ctx, s.ConsumerContract.Babylon)
	s.Len(history, 2)
	history = s.ConsumerCli.App.WasmKeeper.GetContractHistory(ctx, s.ConsumerContract.BTCLightClient)
	s.Len(history, 2)
	history = s.ConsumerCli.App.WasmKeeper.GetContractHistory(ctx, s.ConsumerContract.BTCStaking)
	s.Len(history, 2)
	history = s.ConsumerCli.App.WasmKeeper.GetContractHistory(ctx, s.ConsumerContract.BTCFinality)
	s.Len(history, 2)
}

// TearDownSuite runs once after all the suite's tests have been run
func (s *ContractMigrationSuite) TearDownSuite() {
	// Cleanup code here
}
