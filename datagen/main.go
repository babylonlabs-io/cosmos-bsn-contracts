package main

import (
	"github.com/babylonlabs-io/cosmos-bsn-contracts/datagen/utils"
)

const (
	mainHeadersLength   = 100
	initialHeaderHeight = 1
	forkHeaderHeight    = 90
	testDataPath        = "./packages/test-utils/testdata/"
)

// generating testdata for testing Go <-> Rust protobuf serialisation
func main() {
	utils.GenRawCheckpoint(testDataPath)
	mainHeaders := utils.GenBTCLightClient(initialHeaderHeight, mainHeadersLength, testDataPath)
	utils.GenBTCLightClientFork(mainHeadersLength, mainHeaders[forkHeaderHeight-initialHeaderHeight], testDataPath)
	utils.GenBTCLightClientForkMessages(mainHeadersLength, mainHeaders[forkHeaderHeight-initialHeaderHeight], testDataPath)
	utils.GenBTCTimestamp(testDataPath)
	utils.GenBTCDelegationsAndParams(testDataPath)
	utils.GenFinalityData(testDataPath)
}
