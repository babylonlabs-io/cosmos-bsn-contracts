package types

import (
	"encoding/json"
	"testing"

	"cosmossdk.io/log"
	"github.com/babylonlabs-io/babylon-sdk/demo/app"
	ibctesting "github.com/cosmos/ibc-go/v10/testing"
)

// NewCoordinator initializes Coordinator with N TestChain's
func NewCoordinator(t *testing.T, n int) *ibctesting.Coordinator {
	return ibctesting.NewCustomAppCoordinator(t, n, func() (ibctesting.TestingApp, map[string]json.RawMessage) {
		logger := log.NewTestLogger(t)
		consumerApp := app.NewTmpAppWithLogger(logger)
		return consumerApp, consumerApp.DefaultGenesis()
	})
}
