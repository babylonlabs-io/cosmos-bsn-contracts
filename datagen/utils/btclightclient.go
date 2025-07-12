package utils

import (
	"encoding/json"
	"os"
	"path/filepath"

	bbnapp "github.com/babylonlabs-io/babylon/v3/app"
	"github.com/babylonlabs-io/babylon/v3/testutil/datagen"
	"github.com/babylonlabs-io/babylon/v3/types"
	btclctypes "github.com/babylonlabs-io/babylon/v3/x/btclightclient/types"
)

var (
	cdc = bbnapp.GetEncodingConfig().Codec
)

const (
	BTC_LC_FILENAME          = "btc_light_client.dat"
	BTC_LC_FORK_FILENAME     = "btc_light_client_fork.dat"
	BTC_LC_FORK_MSG_FILENAME = "btc_light_client_fork_msg.json"
)

// BtcHeader is a struct for serialising BTC headers.
// Must match the json definition in the Rust code (`./contract/babylon/src/msg/btc_header.rs`).
type BtcHeader struct {
	// Originally protocol version, but repurposed for soft-fork signaling
	Version int32 `json:"version"`
	// Previous block header hash (hex string)
	PrevBlockHash string `json:"prev_blockhash"`
	// Merkle root hash (hex string)
	MerkleRoot string `json:"merkle_root"`
	// Block timestamp
	Time uint32 `json:"time"`
	// The target value below which the blockhash must lie, encoded as a
	// a float (with well-defined rounding, of course).
	Bits uint32 `json:"bits"`
	// Block nonce
	Nonce uint32 `json:"nonce"`
}

// `BtcHeaders` execute msg in Rust code (`./contract/babylon/src/msg/contract.rs`).
type ExecuteMsg struct {
	BtcHeaders *BtcHeaders `json:"btc_headers,omitempty"`
}

type BtcHeaders struct {
	Headers []*BtcHeader `json:"headers"`
}

func GenBTCLightClient(initialHeaderHeight uint32, mainHeadersLength uint32, dir string) []*btclctypes.BTCHeaderInfoResponse {
	headers := datagen.NewBTCHeaderChainWithLength(
		r,
		initialHeaderHeight,
		uint32(net.PowLimit.Uint64()),
		uint32(mainHeadersLength)).GetChainInfoResponse()
	resp := &btclctypes.QueryMainChainResponse{Headers: headers}
	respBytes := cdc.MustMarshal(resp)
	filePath := filepath.Join(dir, BTC_LC_FILENAME)
	if err := os.WriteFile(filePath, respBytes, 0644); err != nil {
		panic(err)
	}
	return headers
}

func GenBTCLightClientFork(
	mainHeadersLength uint32,
	forkHeader *btclctypes.BTCHeaderInfoResponse,
	dir string,
) {
	height := forkHeader.Height
	length := mainHeadersLength - height + 1 // For an accepted fork

	headers := datagen.NewBTCHeaderChainFromParentInfoResponse(r, forkHeader, uint32(length)).GetChainInfoResponse()
	resp := &btclctypes.QueryMainChainResponse{Headers: headers}
	respBytes := cdc.MustMarshal(resp)
	filePath := filepath.Join(dir, BTC_LC_FORK_FILENAME)
	if err := os.WriteFile(filePath, respBytes, 0644); err != nil {
		panic(err)
	}
}

func GenBTCLightClientForkMessages(
	mainHeadersLength uint32,
	forkHeader *btclctypes.BTCHeaderInfoResponse,
	dir string,
) {
	height := forkHeader.Height
	length := mainHeadersLength - height + 1 // For an accepted fork

	headers := datagen.NewBTCHeaderChainFromParentInfoResponse(r, forkHeader, uint32(length)).GetChainInfoResponse()
	btc_headers := make([]*BtcHeader, len(headers))
	for i := 0; i < len(headers); i++ {
		// Decode the header's header to a BlockHeader struct
		headerBytes, err := types.NewBTCHeaderBytesFromHex(headers[i].HeaderHex)
		if err != nil {
			panic(err)
		}
		blockHeader := headerBytes.ToBlockHeader()

		btc_headers[i] = &BtcHeader{
			Version:       blockHeader.Version,
			PrevBlockHash: blockHeader.PrevBlock.String(),
			MerkleRoot:    blockHeader.MerkleRoot.String(),
			Time:          uint32(blockHeader.Timestamp.Unix()),
			Bits:          blockHeader.Bits,
			Nonce:         blockHeader.Nonce,
		}
	}
	headerChain := &ExecuteMsg{
		BtcHeaders: &BtcHeaders{
			Headers: btc_headers,
		},
	}

	// Marshall to JSON
	respBytes, err := json.Marshal(headerChain)
	if err != nil {
		panic(err)
	}
	filePath := filepath.Join(dir, BTC_LC_FORK_MSG_FILENAME)
	if err := os.WriteFile(filePath, respBytes, 0644); err != nil {
		panic(err)
	}
}
