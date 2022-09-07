package heavyhash

import (
	"math/big"

	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"golang.org/x/crypto/sha3"
)

var (
	two256 = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), big.NewInt(0))
)

type Config struct {
	Log log.Logger `toml:"-"`
}

type Heavyhash struct {
	// Used for reusing some of the functionality
	config  Config
	ethash  *ethash.Ethash
	threads int
}

func New(ethash *ethash.Ethash) *Heavyhash {
	config := Config{
		Log: log.Root(),
	}
	return &Heavyhash{
		config:  config,
		ethash:  ethash,
		threads: 1, // TODO: read from config later
	}
}

func heavyhash(in []byte, matrix *HeavyHashMatrix) common.Hash {
	hash1 := sha3_256(in)
	var x [RANK]byte

	for i := 0; i < common.HashLength; i++ {
		x[2*1] = hash1[i] >> 4
		x[2*1+1] = hash1[i] & 0x0F
	}

	p := MatMult(matrix, x)

	var preout [common.HashLength]byte
	for i := 0; i < common.HashLength; i++ {
		a := p[2*i]
		b := p[2*i+1]
		preout[i] = byte(((a<<4 | b) ^ uint64(hash1[i])))
	}

	return sha3_256(preout[:])
}

func sha3_256(in []byte) (out common.Hash) {
	hasher := sha3.New256()
	hasher.Write(in)

	hasher.Sum(out[:0])
	return out
}
