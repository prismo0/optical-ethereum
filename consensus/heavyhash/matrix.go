package heavyhash

import "github.com/ethereum/go-ethereum/common"

const RANK = 64

type HeavyHashMatrix [RANK][RANK]uint8

func GetHeavyHashMatrix(seed common.Hash) *HeavyHashMatrix {
	var matrix HeavyHashMatrix

	matrix.fill(
		InitXorShiftGen(seed),
	)

	return &matrix
}

func (m *HeavyHashMatrix) fill(xs *XorShiftGen) {
	var value uint64
	for i := 0; i < RANK; i++ {
		for j := 0; j < RANK; j += 16 {
			value = xs.Next()
			for shift := 0; shift < 16; shift++ {
				(*m)[i][j+shift] = uint8((value >> (4 * shift)) & 0xF)
			}
		}
	}
}

func MatMult(m *HeavyHashMatrix, v [RANK]byte) (p [RANK]uint64) {
	for row := 0; row < RANK; row++ {
		for col := 0; col < RANK; col++ {
			p[row] += uint64((*m)[row][col] * v[col])
		}
	}
	return p
}
