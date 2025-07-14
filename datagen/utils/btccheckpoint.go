package utils

import (
	"os"
	"path/filepath"

	"github.com/babylonlabs-io/babylon/v3/testutil/datagen"
)

const (
	RAW_CKPT_FILENAME = "raw_ckpt.dat"
)

func GenRawCheckpoint(dir string) {
	randomRawCkpt := datagen.GenRandomRawCheckpoint(r)
	randomRawCkpt.EpochNum = 12345
	randomRawCkptBytes, err := randomRawCkpt.Marshal()
	if err != nil {
		panic(err)
	}
	filePath := filepath.Join(dir, RAW_CKPT_FILENAME)
	if err := os.WriteFile(filePath, randomRawCkptBytes, 0644); err != nil {
		panic(err)
	}
}
