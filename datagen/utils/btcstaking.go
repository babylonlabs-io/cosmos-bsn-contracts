package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkmath "cosmossdk.io/math"
	"github.com/babylonlabs-io/babylon/v3/testutil/datagen"
	bbn "github.com/babylonlabs-io/babylon/v3/types"
	"github.com/babylonlabs-io/babylon/v3/x/btcstaking/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

const (
	FP_FILENAME                    = "finality_provider_%d.dat"
	FP_SK_FILENAME                 = "fp_sk_%d.dat"
	BTC_DEL_FILENAME               = "btc_delegation_%d_{%s}.dat"
	BTC_DEL_UNBONDING_SIG_FILENAME = "btc_unbonding_sig_%d_{%s}.dat"
	BTCSTAKING_PARAMS_FILENAME     = "btcstaking_params.dat"
)

var (
	fpSK *btcec.PrivateKey
	fpPK *btcec.PublicKey
)

func GenParams(dir string) ([]*btcec.PrivateKey, uint32) {
	t := &testing.T{}

	// (3, 5) covenant committee
	covenantSKs, covenantPKs, err := datagen.GenRandomBTCKeyPairs(r, 5)
	require.NoError(t, err)
	covenantQuorum := uint32(3)

	slashingAddress, err := datagen.GenRandomBTCAddress(r, net)
	require.NoError(t, err)
	slashingPkScript, err := txscript.PayToAddrScript(slashingAddress)
	require.NoError(t, err)

	bsParams := &types.Params{
		CovenantPks:         bbn.NewBIP340PKsFromBTCPKs(covenantPKs),
		CovenantQuorum:      covenantQuorum,
		SlashingPkScript:    slashingPkScript,
		MinSlashingTxFeeSat: 1000,
	}

	paramsBytes, err := bsParams.Marshal()
	require.NoError(t, err)
	paramsPath := filepath.Join(dir, BTCSTAKING_PARAMS_FILENAME)
	err = os.WriteFile(paramsPath, paramsBytes, 0644)
	require.NoError(t, err)

	return covenantSKs, covenantQuorum
}

func getParams(dir string) (*types.Params, error) {
	params, err := os.ReadFile(filepath.Join(dir, BTCSTAKING_PARAMS_FILENAME))
	if err != nil {
		return nil, err
	}
	bsParams := types.Params{}
	err = bsParams.Unmarshal(params)
	return &bsParams, err
}

func GenFinalityProviders(dir string, numFPs int) {
	t := &testing.T{}

	for i := 1; i <= numFPs; i++ {
		fpBTCSK, fpBTCPK, err := datagen.GenRandomBTCKeyPair(r)
		require.NoError(t, err)

		// set the first FP's BTC key pair as the global BTC key pair
		// they will be used for generating public randomness and finality signatures
		if i == 1 {
			fpSK = fpBTCSK
			fpPK = fpBTCPK
		}

		fp, err := datagen.GenRandomFinalityProviderWithBTCSK(r, fpBTCSK, "", "")
		require.NoError(t, err)
		fp.BsnId = fmt.Sprintf("bsn-%d", i)
		fpBytes, err := fp.Marshal()
		require.NoError(t, err)

		fileName := fmt.Sprintf(FP_FILENAME, i)
		fpPath := filepath.Join(dir, fileName)
		err = os.WriteFile(fpPath, fpBytes, 0644)
		require.NoError(t, err)

		// write FP's BTC SK to file
		fpSKBytes := fpBTCSK.Serialize()
		fileName = fmt.Sprintf(FP_SK_FILENAME, i)
		fpSKPath := filepath.Join(dir, fileName)
		err = os.WriteFile(fpSKPath, fpSKBytes, 0644)
		require.NoError(t, err)
	}
}

func getFinalityProvider(dir string, i int) (*types.FinalityProvider, error) {
	fileName := fmt.Sprintf(FP_FILENAME, i)
	fpPath := filepath.Join(dir, fileName)
	fpBytes, err := os.ReadFile(fpPath)
	if err != nil {
		return nil, fmt.Errorf("error reading finality provider %d: %w", i, err)
	}

	fp := &types.FinalityProvider{}
	err = fp.Unmarshal(fpBytes)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling finality provider %d: %w", i, err)
	}

	return fp, nil
}

func getFinalityProviders(dir string, numFPs int) ([]*types.FinalityProvider, error) {
	fps := make([]*types.FinalityProvider, numFPs)
	for i := 1; i <= numFPs; i++ {
		fp, err := getFinalityProvider(dir, i)
		if err != nil {
			return nil, err
		}
		fps[i-1] = fp
	}
	return fps, nil
}

func GenBTCDelegations(dir string, covenantSKs []*btcec.PrivateKey, covenantQuorum uint32, idx int, fpIdxList []int) {
	t := &testing.T{}

	// read params
	bsParams, err := getParams(dir)
	require.NoError(t, err)

	// read finality providers' BTC PKs
	fpBTCPKs := make([]bbn.BIP340PubKey, len(fpIdxList))
	for i, idx := range fpIdxList {
		fp, err := getFinalityProvider(dir, idx)
		require.NoError(t, err)
		fpBTCPKs[i] = *fp.BtcPk
	}

	delSK, _, err := datagen.GenRandomBTCKeyPair(r)
	require.NoError(t, err)

	stakingTimeBlocks := uint16(5)
	stakingValue := int64(2 * 10e8)

	slashingRate := sdkmath.LegacyNewDecWithPrec(int64(datagen.RandomInt(r, 41)+10), 2)
	unbondingTime := uint16(100) + 1
	slashingChangeLockTime := unbondingTime

	// only the quorum of signers provided the signatures
	covenantSigners := covenantSKs[:covenantQuorum]

	covPKs, err := bbn.NewBTCPKsFromBIP340PKs(bsParams.CovenantPks)
	require.NoError(t, err)

	// construct the BTC delegation with everything
	btcDel, err := datagen.GenRandomBTCDelegation(
		r,
		t,
		net,
		fpBTCPKs,
		delSK,
		"",
		covenantSigners,
		covPKs,
		covenantQuorum,
		bsParams.SlashingPkScript,
		uint32(stakingTimeBlocks),
		1000,
		uint32(1000+stakingTimeBlocks),
		uint64(stakingValue),
		slashingRate,
		slashingChangeLockTime,
	)
	require.NoError(t, err)

	btcDelBytes, err := btcDel.Marshal()
	require.NoError(t, err)

	// filename
	fpIdxListStr := make([]string, len(fpIdxList))
	for i, idx := range fpIdxList {
		fpIdxListStr[i] = fmt.Sprintf("%d", idx)
	}
	fileName := fmt.Sprintf(BTC_DEL_FILENAME, idx, strings.Join(fpIdxListStr, ","))

	btcDelPath := filepath.Join(dir, fileName)
	err = os.WriteFile(btcDelPath, btcDelBytes, 0644)
	require.NoError(t, err)

	// sign unbonding signature
	unbondingSig, err := btcDel.SignUnbondingTx(bsParams, net, delSK)
	require.NoError(t, err)
	unbondingSigBytes := unbondingSig.Serialize()
	// write unbonding signature to file
	fileName = fmt.Sprintf(BTC_DEL_UNBONDING_SIG_FILENAME, idx, strings.Join(fpIdxListStr, ","))
	unbondingSigPath := filepath.Join(dir, fileName)
	err = os.WriteFile(unbondingSigPath, unbondingSigBytes, 0644)
	require.NoError(t, err)
}

func GenBTCDelegationsAndParams(dir string) {
	covenantSKs, covenantQuorum := GenParams(dir)
	// 3 FPs
	GenFinalityProviders(dir, 3)
	// 3 BTC delegations under 1st FPs
	GenBTCDelegations(dir, covenantSKs, covenantQuorum, 1, []int{1})
	GenBTCDelegations(dir, covenantSKs, covenantQuorum, 2, []int{1})
	GenBTCDelegations(dir, covenantSKs, covenantQuorum, 3, []int{1})
	// 3 BTC delegations under 2nd FPs
	GenBTCDelegations(dir, covenantSKs, covenantQuorum, 1, []int{2})
	GenBTCDelegations(dir, covenantSKs, covenantQuorum, 2, []int{2})
	GenBTCDelegations(dir, covenantSKs, covenantQuorum, 3, []int{2})
	// a BTC delegation restaked to 1/3-th FPs
	GenBTCDelegations(dir, covenantSKs, covenantQuorum, 1, []int{1, 3})
}
