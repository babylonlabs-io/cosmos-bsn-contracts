package utils

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/cometbft/cometbft/crypto/merkle"

	"github.com/babylonlabs-io/babylon/v3/app/signingcontext"
	"github.com/babylonlabs-io/babylon/v3/crypto/eots"
	"github.com/babylonlabs-io/babylon/v3/testutil/datagen"
	bbn "github.com/babylonlabs-io/babylon/v3/types"
	ftypes "github.com/babylonlabs-io/babylon/v3/x/finality/types"
)

const (
	MSG_COMMIT_PUB_RAND  = "commit_pub_rand_msg.dat"
	PUB_RAND_VALUE       = "pub_rand_value.dat"
	MSG_ADD_FINALITY_SIG = "add_finality_sig_%d_msg.dat"
)

const (
	commitPubRandHeight     = 100
	commitPubRandAmount     = 1000
	pubRandIndex            = 1
	babylonChainID          = "babylon-testnet-phase-3"
	btcFinalityContractAddr = "cosmwasm17p9rzwnnfxcjp32un9ug7yhhzgtkhvl9jfksztgw5uh69wac2pgsnuzwl9"
)

func GenRandomPubRandList(r *rand.Rand, numPubRand uint64) (*datagen.RandListInfo, error) {
	// generate a list of secret/public randomness
	var srList []*eots.PrivateRand
	var prList []bbn.SchnorrPubRand
	for i := uint64(0); i < numPubRand; i++ {
		eotsSR, eotsPR, err := eots.RandGen(r)
		if err != nil {
			return nil, err
		}
		pr := bbn.NewSchnorrPubRandFromFieldVal(eotsPR)
		srList = append(srList, eotsSR)
		prList = append(prList, *pr)
	}

	var prByteList [][]byte
	for i := range prList {
		prByteList = append(prByteList, prList[i])
	}

	// generate the commitment to these public randomness
	commitment, proofList := merkle.ProofsFromByteSlices(prByteList)

	return &datagen.RandListInfo{SRList: srList, PRList: prList, Commitment: commitment, ProofList: proofList}, nil
}

func GenCommitPubRandListMsg(startHeight uint64, numPubRand uint64, pubRandIndex uint64, sk *btcec.PrivateKey, signingContext string, dir string) *datagen.RandListInfo {
	randListInfo, err := GenRandomPubRandList(r, numPubRand)
	if err != nil {
		panic(err)
	}

	msg := &ftypes.MsgCommitPubRandList{
		Signer:      datagen.GenRandomAccount().Address,
		FpBtcPk:     bbn.NewBIP340PubKeyFromBTCPK(sk.PubKey()),
		StartHeight: startHeight,
		NumPubRand:  numPubRand,
		Commitment:  randListInfo.Commitment,
	}
	hash, err := msg.HashToSign(signingContext)
	if err != nil {
		panic(err)
	}
	schnorrSig, err := schnorr.Sign(sk, hash)
	if err != nil {
		panic(err)
	}
	msg.Sig = bbn.NewBIP340SignatureFromBTCSig(schnorrSig)

	msgCommitPubRandBytes, err := msg.Marshal()
	if err != nil {
		panic(err)
	}

	msgCommitPubRandPath := filepath.Join(dir, MSG_COMMIT_PUB_RAND)
	err = os.WriteFile(msgCommitPubRandPath, msgCommitPubRandBytes, 0644)
	if err != nil {
		panic(err)
	}

	pubRandValue := randListInfo.PRList[pubRandIndex]
	pubRandPath := filepath.Join(dir, PUB_RAND_VALUE)
	err = os.WriteFile(pubRandPath, pubRandValue, 0644)
	if err != nil {
		panic(err)
	}

	return randListInfo
}

func NewMsgAddFinalitySig(
	signer string,
	sk *btcec.PrivateKey,
	signingContext string,
	startHeight uint64,
	blockHeight uint64,
	randListInfo *datagen.RandListInfo,
	blockAppHash []byte,
) (*ftypes.MsgAddFinalitySig, error) {
	idx := blockHeight - startHeight

	msg := &ftypes.MsgAddFinalitySig{
		Signer:       signer,
		FpBtcPk:      bbn.NewBIP340PubKeyFromBTCPK(sk.PubKey()),
		PubRand:      &randListInfo.PRList[idx],
		Proof:        randListInfo.ProofList[idx].ToProto(),
		BlockHeight:  blockHeight,
		BlockAppHash: blockAppHash,
		FinalitySig:  nil,
	}
	msgToSign := msg.MsgToSign(signingContext)
	sig, err := eots.Sign(sk, randListInfo.SRList[idx], msgToSign)
	if err != nil {
		return nil, err
	}
	msg.FinalitySig = bbn.NewSchnorrEOTSSigFromModNScalar(sig)

	return msg, nil
}

func GenAddFinalitySig(startHeight uint64, index uint64, randListInfo *datagen.RandListInfo, sk *btcec.PrivateKey, signingContext string, dir string, signatureIndex uint32) *ftypes.MsgAddFinalitySig {
	blockHeight := startHeight + index
	blockHash := datagen.GenRandomByteArray(r, 32)

	signer := datagen.GenRandomAccount().Address
	msg, err := NewMsgAddFinalitySig(signer, sk, signingContext, startHeight, blockHeight, randListInfo, blockHash)
	if err != nil {
		panic(err)
	}

	msgAddFinalitySigBytes, err := msg.Marshal()
	if err != nil {
		panic(err)
	}

	msgCommitPubRandPath := filepath.Join(dir, fmt.Sprintf(MSG_ADD_FINALITY_SIG, signatureIndex))
	err = os.WriteFile(msgCommitPubRandPath, msgAddFinalitySigBytes, 0644)
	if err != nil {
		panic(err)
	}
	return msg
}

/*
func GenRandomEvidence(r *rand.Rand, sk *btcec.PrivateKey, height uint64) (*ftypes.Evidence, error) {
	pk := sk.PubKey()
	bip340PK := bbn.NewBIP340PubKeyFromBTCPK(pk)
	sr, pr, err := eots.RandGen(r)
	if err != nil {
		return nil, err
	}
	cAppHash := GenRandomByteArray(r, 32)
	cSig, err := eots.Sign(sk, sr, append(sdk.Uint64ToBigEndian(height), cAppHash...))
	if err != nil {
		return nil, err
	}
	fAppHash := GenRandomByteArray(r, 32)
	fSig, err := eots.Sign(sk, sr, append(sdk.Uint64ToBigEndian(height), fAppHash...))
	if err != nil {
		return nil, err
	}

	evidence := &ftypes.Evidence{
		FpBtcPk:              bip340PK,
		BlockHeight:          height,
		PubRand:              bbn.NewSchnorrPubRandFromFieldVal(pr),
		CanonicalAppHash:     cAppHash,
		ForkAppHash:          fAppHash,
		CanonicalFinalitySig: bbn.NewSchnorrEOTSSigFromModNScalar(cSig),
		ForkFinalitySig:      bbn.NewSchnorrEOTSSigFromModNScalar(fSig),
	}
	return evidence, nil
}
*/

func GenFinalityData(dir string) {
	GenEOTSTestData(dir)
	pubRandSigningContext := signingcontext.FpRandCommitContextV0(babylonChainID, btcFinalityContractAddr)
	randListInfo := GenCommitPubRandListMsg(commitPubRandHeight, commitPubRandAmount, pubRandIndex, fpSK, pubRandSigningContext, dir)
	fpSigningContext := signingcontext.FpFinVoteContextV0(babylonChainID, btcFinalityContractAddr)
	GenAddFinalitySig(commitPubRandHeight, pubRandIndex, randListInfo, fpSK, fpSigningContext, dir, 1)
	// Conflicting signature / double signing
	GenAddFinalitySig(commitPubRandHeight, pubRandIndex, randListInfo, fpSK, fpSigningContext, dir, 2)
}
