package heavyhash

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
)

type XorShiftGen struct {
	state [4]uint64
}

func InitXorShiftGen(seed common.Hash) *XorShiftGen {
	var xs XorShiftGen

	xs.state[0] = binary.BigEndian.Uint64(seed[0:8])
	xs.state[1] = binary.BigEndian.Uint64(seed[8:16])
	xs.state[2] = binary.BigEndian.Uint64(seed[16:24])
	xs.state[3] = binary.BigEndian.Uint64(seed[24:32])

	return &xs
}

func (xs *XorShiftGen) Next() uint64 {
	result := xs.rotateLeft64(xs.state[0]+xs.state[3], 23) + xs.state[0]

	var t uint64 = xs.state[1] << 17

	xs.state[2] ^= xs.state[0]
	xs.state[3] ^= xs.state[1]
	xs.state[1] ^= xs.state[2]
	xs.state[0] ^= xs.state[3]

	xs.state[2] ^= t

	xs.state[3] = xs.rotateLeft64(xs.state[3], 45)

	return result
}

func (xs *XorShiftGen) rotateLeft64(x uint64, k int) uint64 {
	return (x << k) | (x >> (64 - k))
}
