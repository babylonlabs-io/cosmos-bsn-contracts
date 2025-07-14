package utils

import (
	"os"
	"path/filepath"
	"testing"

	txformat "github.com/babylonlabs-io/babylon/v3/btctxformatter"
	"github.com/babylonlabs-io/babylon/v3/crypto/bls12381"
	"github.com/babylonlabs-io/babylon/v3/testutil/datagen"
	testhelper "github.com/babylonlabs-io/babylon/v3/testutil/helper"
	btcctypes "github.com/babylonlabs-io/babylon/v3/x/btccheckpoint/types"
	ckpttypes "github.com/babylonlabs-io/babylon/v3/x/checkpointing/types"
	zctypes "github.com/babylonlabs-io/babylon/v3/x/zoneconcierge/types"
	"github.com/boljen/go-bitmap"
	"github.com/stretchr/testify/require"
)

const (
	BTC_TS_FILENAME         = "btc_timestamp.dat"
	BTC_TS_HEADER0_FILENAME = "btc_timestamp_header0.dat"
	BTC_TS_HEADER1_FILENAME = "btc_timestamp_header1.dat"
)

func signBLSWithBitmap(blsSKs []bls12381.PrivateKey, bm bitmap.Bitmap, msg []byte) (bls12381.Signature, error) {
	sigs := []bls12381.Signature{}
	for i := 0; i < len(blsSKs); i++ {
		if bitmap.Get(bm, i) {
			sig := bls12381.Sign(blsSKs[i], msg)
			sigs = append(sigs, sig)
		}
	}
	return bls12381.AggrSigList(sigs)
}

func GenBTCTimestamp(dir string) {
	t := &testing.T{}
	valSet, privSigner, err := datagen.GenesisValidatorSetWithPrivSigner(10)
	if err != nil {
		panic(err)
	}
	h := testhelper.NewHelperWithValSet(t, valSet, privSigner)
	ek := &h.App.EpochingKeeper
	zck := h.App.ZoneConciergeKeeper

	// empty BTC timestamp
	btcTs := &zctypes.BTCTimestamp{}
	btcTs.Proof = &zctypes.ProofFinalizedChainInfo{}

	// chain is at height 1 thus epoch 1

	/*
		generate Consumer header and its inclusion proof to an epoch
	*/
	// enter block 11, 1st block of epoch 2
	epochInterval := ek.GetParams(h.Ctx).EpochInterval
	for j := 0; j < int(epochInterval); j++ {
		h.Ctx, err = h.ApplyEmptyBlockWithVoteExtension(r)
		h.NoError(err)
	}

	// handle a random header from a random consumer chain
	consumerID := datagen.GenRandomHexStr(r, 10)
	height := datagen.RandomInt(r, 100) + 1
	ibctmHeader := datagen.GenRandomIBCTMHeader(r, height)
	zck.HandleHeaderWithValidCommit(h.Ctx, datagen.GenRandomByteArray(r, 32), datagen.NewZCHeaderInfo(ibctmHeader, consumerID), false)

	// ensure the header is successfully inserted
	indexedHeader, err := zck.GetHeader(h.Ctx, consumerID, height)
	h.NoError(err)

	// enter block 21, 1st block of epoch 3
	for j := 0; j < int(epochInterval); j++ {
		h.Ctx, err = h.ApplyEmptyBlockWithVoteExtension(r)
		h.NoError(err)
	}
	// seal last epoch
	h.Ctx, err = h.ApplyEmptyBlockWithVoteExtension(r)
	h.NoError(err)

	epochWithHeader, err := ek.GetHistoricalEpoch(h.Ctx, indexedHeader.BabylonEpoch)
	h.NoError(err)

	// generate inclusion proof
	proof, err := zck.ProveConsumerHeaderInEpoch(h.Ctx, indexedHeader, epochWithHeader)
	h.NoError(err)

	btcTs.EpochInfo = epochWithHeader
	btcTs.Header = indexedHeader
	btcTs.Proof.ProofConsumerHeaderInEpoch = proof

	/*
		seal the epoch and generate ProofEpochSealed
	*/
	// construct the rawCkpt
	// Note that the BlsMultiSig will be generated and assigned later
	bm := datagen.GenFullBitmap()
	sealerBlockhash := ckpttypes.BlockHash(epochWithHeader.SealerBlockHash)
	rawCkpt := &ckpttypes.RawCheckpoint{
		EpochNum:    epochWithHeader.EpochNumber,
		BlockHash:   &sealerBlockhash,
		Bitmap:      bm,
		BlsMultiSig: nil,
	}
	// let the subset generate a BLS multisig over sealer header's app_hash
	multiSig, err := signBLSWithBitmap(h.GenValidators.GetBLSPrivKeys(), bm, rawCkpt.SignedMsg())
	require.NoError(t, err)
	// assign multiSig to rawCkpt
	rawCkpt.BlsMultiSig = &multiSig

	// prove
	btcTs.Proof.ProofEpochSealed, err = zck.ProveEpochSealed(h.Ctx, epochWithHeader.EpochNumber)
	require.NoError(t, err)

	btcTs.RawCheckpoint = rawCkpt

	/*
		forge two BTC headers including the checkpoint
	*/
	// encode ckpt to BTC txs in BTC blocks
	submitterAddr := datagen.GenRandomByteArray(r, txformat.AddressLength)
	rawBTCCkpt, err := ckpttypes.FromRawCkptToBTCCkpt(rawCkpt, submitterAddr)
	h.NoError(err)
	testRawCkptData := datagen.EncodeRawCkptToTestData(rawBTCCkpt)
	idxs := []uint64{datagen.RandomInt(r, 5) + 1, datagen.RandomInt(r, 5) + 1}
	offsets := []uint64{datagen.RandomInt(r, 5) + 1, datagen.RandomInt(r, 5) + 1}
	btcBlocks := []*datagen.BlockCreationResult{
		datagen.CreateBlock(r, 1, uint32(idxs[0]+offsets[0]), uint32(idxs[0]), testRawCkptData.FirstPart),
		datagen.CreateBlock(r, 2, uint32(idxs[1]+offsets[1]), uint32(idxs[1]), testRawCkptData.SecondPart),
	}
	// create MsgInsertBtcSpvProof for the rawCkpt
	msgInsertBtcSpvProof := datagen.GenerateMessageWithRandomSubmitter([]*datagen.BlockCreationResult{btcBlocks[0], btcBlocks[1]})

	// assign BTC submission key and ProofEpochSubmitted
	btcTs.BtcSubmissionKey = &btcctypes.SubmissionKey{
		Key: []*btcctypes.TransactionKey{
			&btcctypes.TransactionKey{Index: uint32(idxs[0]), Hash: btcBlocks[0].HeaderBytes.Hash()},
			&btcctypes.TransactionKey{Index: uint32(idxs[1]), Hash: btcBlocks[1].HeaderBytes.Hash()},
		},
	}
	btcTs.Proof.ProofEpochSubmitted = []*btcctypes.TransactionInfo{
		{
			Key:         btcTs.BtcSubmissionKey.Key[0],
			Transaction: msgInsertBtcSpvProof.Proofs[0].BtcTransaction,
			Proof:       msgInsertBtcSpvProof.Proofs[0].MerkleNodes,
		},
		{
			Key:         btcTs.BtcSubmissionKey.Key[1],
			Transaction: msgInsertBtcSpvProof.Proofs[1].BtcTransaction,
			Proof:       msgInsertBtcSpvProof.Proofs[1].MerkleNodes,
		},
	}

	// save BTC timestamp as test data
	btcTsBytes := cdc.MustMarshal(btcTs)
	btcTsPath := filepath.Join(dir, BTC_TS_FILENAME)
	if err := os.WriteFile(btcTsPath, btcTsBytes, 0644); err != nil {
		panic(err)
	}

	// save BTC headers that include the BTC timestamp
	header0Path := filepath.Join(dir, BTC_TS_HEADER0_FILENAME)
	if err := os.WriteFile(header0Path, btcBlocks[0].HeaderBytes, 0644); err != nil {
		panic(err)
	}
	header1Path := filepath.Join(dir, BTC_TS_HEADER1_FILENAME)
	if err := os.WriteFile(header1Path, btcBlocks[1].HeaderBytes, 0644); err != nil {
		panic(err)
	}
}
