package utils

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/babylonlabs-io/babylon/v3/crypto/eots"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const (
	EOTS_TESTDATA = "eots_testdata.json"
)

// EotsTestData is the generated data for testing EOTS signature
type EotsTestData struct {
	SK   string `json:"sk"`   // secret key of the signer
	PK   string `json:"pk"`   // public key of the signer
	SR   string `json:"sr"`   // secret randomness
	PR   string `json:"pr"`   // public randomness
	Msg1 string `json:"msg1"` // first message signed
	Msg2 string `json:"msg2"` // second message signed
	Sig1 string `json:"sig1"` // first signature
	Sig2 string `json:"sig2"` // second signature
}

func GenEOTSTestData(dir string) {
	sk, err := eots.KeyGen(r)
	if err != nil {
		panic(err)
	}
	pk := sk.PubKey()
	sr, pr, err := eots.RandGen(r)
	if err != nil {
		panic(err)
	}
	srBytes, prBytes := sr.Bytes(), *pr.Bytes()

	msg1 := []byte("hello world 1")
	msg2 := []byte("hello world 2")

	sig1, err := eots.Sign(sk, sr, msg1)
	if err != nil {
		panic(err)
	}
	sig2, err := eots.Sign(sk, sr, msg2)
	if err != nil {
		panic(err)
	}
	sig1Bytes, sig2Bytes := sig1.Bytes(), sig2.Bytes()

	testData := &EotsTestData{
		SK:   hex.EncodeToString(sk.Serialize()),
		PK:   hex.EncodeToString(schnorr.SerializePubKey(pk)),
		SR:   hex.EncodeToString(srBytes[:]),
		PR:   hex.EncodeToString(prBytes[:]),
		Msg1: hex.EncodeToString(msg1),
		Msg2: hex.EncodeToString(msg2),
		Sig1: hex.EncodeToString(sig1Bytes[:]),
		Sig2: hex.EncodeToString(sig2Bytes[:]),
	}
	testDataBytes, err := json.Marshal(testData)
	if err != nil {
		panic(err)
	}

	filePath := filepath.Join(dir, EOTS_TESTDATA)
	if err := os.WriteFile(filePath, testDataBytes, 0644); err != nil {
		panic(err)
	}
}
