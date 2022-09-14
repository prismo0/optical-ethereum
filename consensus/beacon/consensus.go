// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package beacon

import (
	"errors"
	"math/big"

	mapset "github.com/deckarep/golang-set"
	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/heavyhash"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// Proof-of-stake protocol constants.
var (
	maxUncles        = 2
	beaconDifficulty = common.Big0 // The default block difficulty in the beacon consensus
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	errTooManyUncles   = errors.New("too many uncles")
	errDuplicateUncle  = errors.New("duplicate uncle")
	errUncleIsAncestor = errors.New("uncle is ancestor")
	errDanglingUncle   = errors.New("uncle's parent is not ancestor")
)

// Beacon is a consensus engine that combines the eth1 consensus and proof-of-stake
// algorithm. There is a special flag inside to decide whether to use legacy consensus
// rules or new rules. The transition rule is described in the eth1/2 merge spec.
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3675.md
//
// The beacon here is a half-functional consensus engine with partial functions which
// is only used for necessary consensus checks. The legacy consensus engine can be any
// engine implements the consensus interface (except the beacon itself).
type Beacon struct {
	log                 log.Logger
	ethone              consensus.Engine // Original consensus engine used in eth1, e.g. ethash or clique
	photonicInterceptor consensus.Engine // oPoW concensus engine that activates with TTD reach and results in an adverserial hard-fork
}

// TODO: Check all consensus.Engine methods for correctness (special care for the ones with IsPOSHeader)

func NewPhotonicBeacon(ethone consensus.Engine) *Beacon {
	beacon := New(ethone)

	if _, ok := ethone.(*ethash.Ethash); ok {
		beacon.photonicInterceptor = heavyhash.New(ethone.(*ethash.Ethash))
	}

	return beacon
}

// New creates a consensus engine with the given embedded eth1 engine.
func New(ethone consensus.Engine) *Beacon {
	if _, ok := ethone.(*Beacon); ok {
		panic("nested consensus engine")
	}

	return &Beacon{
		log:    log.Root(),
		ethone: ethone,
	}
}

// Author implements consensus.Engine, returning the verified author of the block.
func (beacon *Beacon) Author(header *types.Header) (common.Address, error) {
	return beacon.ethone.Author(header)
}

// VerifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum consensus engine.
func (beacon *Beacon) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	reached, err := IsTTDReached(chain, header.ParentHash, header.Number.Uint64()-1)
	if err != nil {
		return err
	}
	if !reached {
		return beacon.ethone.VerifyHeader(chain, header, seal)
	}
	return beacon.photonicInterceptor.VerifyHeader(chain, header, seal)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
// VerifyHeaders expect the headers to be ordered and continuous.
func (beacon *Beacon) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	// One before common ancesort

	// What if a brand new node gets attached, then it will have genesis as a common ancestor,
	// which would case all the headers to go be verified by the ethash while only a protion needs to undergo that.
	// Thus, a need for some terminal value, that retrieves a current accpeted diff e.g.

	// there is a need to split blocks into terminal and non-terminal if the state was not known earlier
	var (
		prePhotnicEraIndex int      = 0
		numBlocks          int      = len(headers)
		td                 *big.Int = chain.GetTd(headers[0].ParentHash, headers[0].Number.Uint64()-1)
		terminalDif        uint64   = 0
	)

	// Header list should start from the common ancestor
	if td == nil {
		result := make(chan error, numBlocks)
		for i := 0; i < numBlocks; i++ {
			result <- consensus.ErrUnknownAncestor
		}
		return make(chan<- struct{}), result
	}
	terminalDif = td.Uint64()

	for _, header := range headers {
		if terminalDif >= chain.Config().TerminalTotalDifficulty.Uint64() {
			break
		}
		prePhotnicEraIndex++
		terminalDif += header.Difficulty.Uint64()
	}

	// Execute header verification for edge-cases explicit.
	// Edge-cases are:
	// 1) All recieved blocks are after the beginning of the Photnic Era
	// 2) All recieved blocks are before the beginning of the Photnic Era
	if prePhotnicEraIndex == 0 {
		// All the headers are opow headers. Verify that the parent block reached total terminal difficulty.
		beacon.log.Debug("Headers are exclusively oPoW, after Photnic Era", "algo", "heavyhash")
		return beacon.photonicInterceptor.VerifyHeaders(chain, headers, seals)
	} else if prePhotnicEraIndex == numBlocks {
		beacon.log.Debug("Headers are exclusively PoW, before Photnic Era", "algo", "ethash")
		return beacon.ethone.VerifyHeaders(chain, headers, seals)
	}

	// The transition point exists in the middle, separate the headers
	// into two batches and apply different verification rules for them.
	beacon.log.Debug(
		"The batch is split into pre and post Photonic Era",
		"batch boundary", prePhotnicEraIndex,
		"batch size", numBlocks,
	)
	beacon.log.Debug("Handle the verification gently")
	return beacon.verifyHeaders(chain, headers, seals, nil, prePhotnicEraIndex)
}

// verifyTerminalPoWBlock verifies that the preHeaders conform to the specification
// wrt. their total difficulty.
// It expects:
// - preHeaders to be at least 1 element
// - the parent of the header element to be stored in the chain correctly
// - the preHeaders to have a set difficulty
// - the last element to be the terminal block
func verifyTerminalPoWBlock(chain consensus.ChainHeaderReader, preHeaders []*types.Header) (int, error) {
	td := chain.GetTd(preHeaders[0].ParentHash, preHeaders[0].Number.Uint64()-1)
	if td == nil {
		return 0, consensus.ErrUnknownAncestor
	}
	td = new(big.Int).Set(td)
	// Check that all blocks before the last one are below the TTD
	for i, head := range preHeaders {
		if td.Cmp(chain.Config().TerminalTotalDifficulty) >= 0 {
			return i, consensus.ErrInvalidTerminalBlock
		}
		td.Add(td, head.Difficulty)
	}
	// Check that the last block is the terminal block
	if td.Cmp(chain.Config().TerminalTotalDifficulty) < 0 {
		return len(preHeaders) - 1, consensus.ErrInvalidTerminalBlock
	}
	return 0, nil
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of the Ethereum consensus engine.
func (beacon *Beacon) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	// Verify that there are at most 2 uncles included in this block
	if len(block.Uncles()) > maxUncles {
		return errTooManyUncles
	}
	if len(block.Uncles()) == 0 {
		return nil
	}
	// Gather the set of past uncles and ancestors
	uncles, ancestors := mapset.NewSet(), make(map[common.Hash]*types.Header)

	number, parent := block.NumberU64()-1, block.ParentHash()
	for i := 0; i < 7; i++ {
		ancestorHeader := chain.GetHeader(parent, number)
		if ancestorHeader == nil {
			break
		}
		ancestors[parent] = ancestorHeader
		// If the ancestor doesn't have any uncles, we don't have to iterate them
		if ancestorHeader.UncleHash != types.EmptyUncleHash {
			// Need to add those uncles to the banned list too
			ancestor := chain.GetBlock(parent, number)
			if ancestor == nil {
				break
			}
			for _, uncle := range ancestor.Uncles() {
				uncles.Add(uncle.Hash())
			}
		}
		parent, number = ancestorHeader.ParentHash, number-1
	}
	ancestors[block.Hash()] = block.Header()
	uncles.Add(block.Hash())

	// Verify each of the uncles that it's recent, but not an ancestor
	for _, uncle := range block.Uncles() {
		// Make sure every uncle is rewarded only once
		hash := uncle.Hash()
		if uncles.Contains(hash) {
			return errDuplicateUncle
		}
		uncles.Add(hash)

		// Make sure the uncle has a valid ancestry
		if ancestors[hash] != nil {
			return errUncleIsAncestor
		}
		if ancestors[uncle.ParentHash] == nil || uncle.ParentHash == block.ParentHash() {
			return errDanglingUncle
		}

		// Depending on the uncle's parent total difficulty use oPoW or PoW
		reached := chain.GetTd(uncle.ParentHash, ancestors[uncle.ParentHash].Number.Uint64()).Uint64() >= chain.Config().TerminalTotalDifficulty.Uint64()
		if !reached {
			if err := beacon.ethone.(*ethash.Ethash).VerifyBoundaryHeader(chain, uncle, ancestors[uncle.ParentHash], true, true); err != nil {
				return err
			}
		} else {
			if err := beacon.photonicInterceptor.(*heavyhash.Heavyhash).VerifyBoundaryHeader(chain, uncle, ancestors[uncle.ParentHash], true, true); err != nil {
				return err
			}
		}
	}
	return nil
}

// verifyHeaders is similar to verifyHeader, but it verifies a batch of headers
// concurrently.
// The method handles boundary verification for a batch that contains headers
// both before the Photnic Era and after it.
// The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications. An additional `ancestor`
// header will be passed if the relevant header is not in the database yet.
// A `prePhotonicEraIndex` is passed to signal about the location of the boundary block
// in the list of headers.
func (beacon *Beacon) verifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool, ancestor *types.Header, prePhotnicEraIndex int) (chan<- struct{}, <-chan error) {
	var (
		abort   = make(chan struct{})
		results = make(chan error, len(headers))
	)
	// TODO: potentially split run the verification concurrently
	go func() {
		for i, header := range headers {
			var parent *types.Header
			var seal bool = seals[i]
			if i == 0 {
				if ancestor != nil {
					parent = ancestor
				} else {
					parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
				}
			} else if headers[i-1].Hash() == headers[i].ParentHash {
				parent = headers[i-1]
			}
			if parent == nil {
				select {
				case <-abort:
					return
				case results <- consensus.ErrUnknownAncestor:
				}
				continue
			}
			var err error
			if i >= prePhotnicEraIndex {
				err = beacon.photonicInterceptor.(*heavyhash.Heavyhash).VerifyBoundaryHeader(chain, header, parent, false, seal)
			} else {
				err = beacon.ethone.(*ethash.Ethash).VerifyBoundaryHeader(chain, header, parent, false, seal)
			}
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// Prepare implements consensus.Engine, initializing the difficulty field of a
// header to conform to the beacon protocol. The changes are done inline.
func (beacon *Beacon) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	// Transition isn't triggered yet, use the legacy rules for preparation.
	reached, err := IsTTDReached(chain, header.ParentHash, header.Number.Uint64()-1)
	if err != nil {
		return err
	}
	if !reached {
		return beacon.ethone.Prepare(chain, header)
	}
	return beacon.photonicInterceptor.Prepare(chain, header)
}

// Finalize implements consensus.Engine, setting the final state on the header
func (beacon *Beacon) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	// Finalize is different with Prepare, it can be used in both block generation
	// and verification. So determine the consensus rules by header type.
	reached, _ := IsTTDReached(chain, header.ParentHash, header.Number.Uint64()-1)
	if !reached {
		beacon.ethone.Finalize(chain, header, state, txs, uncles)
		return
	}
	beacon.photonicInterceptor.Finalize(chain, header, state, txs, uncles)
}

// FinalizeAndAssemble implements consensus.Engine, setting the final state and
// assembling the block.
func (beacon *Beacon) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// FinalizeAndAssemble is different with Prepare, it can be used in both block
	// generation and verification. So determine the consensus rules by header type.
	reached, _ := IsTTDReached(chain, header.ParentHash, header.Number.Uint64()-1)
	if !reached {
		return beacon.ethone.FinalizeAndAssemble(chain, header, state, txs, uncles, receipts)
	}
	return beacon.photonicInterceptor.FinalizeAndAssemble(chain, header, state, txs, uncles, receipts)
}

// Seal generates a new sealing request for the given input block and pushes
// the result into the given channel.
//
// Note, the method returns immediately and will send the result async. More
// than one result may also be returned depending on the consensus algorithm.
func (beacon *Beacon) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()
	reached, _ := IsTTDReached(chain, header.ParentHash, header.Number.Uint64()-1)
	if !reached {
		beacon.log.Debug("Sealing blocks", "algo", "ethash")
		return beacon.ethone.Seal(chain, block, results, stop)
	}
	beacon.log.Debug("Sealing blocks", "algo", "heavyhash")
	return beacon.photonicInterceptor.Seal(chain, block, results, stop)
}

// SealHash returns the hash of a block prior to it being sealed.
func (beacon *Beacon) SealHash(header *types.Header) common.Hash {
	return beacon.ethone.SealHash(header)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
func (beacon *Beacon) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	// Transition isn't triggered yet, use the legacy rules for calculation
	if reached, _ := IsTTDReached(chain, parent.Hash(), parent.Number.Uint64()); !reached {
		beacon.log.Info("Calculating diff", "algo", "ethash")
		return beacon.ethone.CalcDifficulty(chain, time, parent)
	}
	beacon.log.Info("Calculating diff", "algo", "heavyhash")
	// TODO: Disable diff bombs
	return beacon.photonicInterceptor.CalcDifficulty(chain, time, parent)
}

// APIs implements consensus.Engine, returning the user facing RPC APIs.
func (beacon *Beacon) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return beacon.ethone.APIs(chain)
}

// Close shutdowns the consensus engine
func (beacon *Beacon) Close() error {
	return beacon.ethone.Close()
}

// IsPoSHeader reports the header belongs to the PoS-stage with some special fields.
// This function is not suitable for a part of APIs like Prepare or CalcDifficulty
// because the header difficulty is not set yet.
func (beacon *Beacon) IsPoSHeader(header *types.Header) bool {
	// TODO: most likely return false by default
	// For now monitoring for occurances
	if header.Difficulty == nil {
		panic("IsPoSHeader called with invalid difficulty")
	}
	fPoSHeader := header.Difficulty.Cmp(beaconDifficulty) == 0
	if fPoSHeader {
		beacon.log.Warn(
			"PoS header encountered. Data from beacon chain leaks into the oPoW fork",
			"msg", "please contact the dev team",
			"email", "prismo.dark@proton.me",
		)
	}
	return fPoSHeader
}

// InnerEngine returns the embedded eth1 consensus engine.
func (beacon *Beacon) InnerEngine() consensus.Engine {
	return beacon.ethone
}

// InnerEngine returns the embedded opow consensus engine.
func (beacon *Beacon) OPOWEngine() consensus.Engine {
	return beacon.photonicInterceptor
}

// SetThreads updates the mining threads. Delegate the call
// to the eth1 engine if it's threaded.
func (beacon *Beacon) SetThreads(threads int) {
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := beacon.ethone.(threaded); ok {
		th.SetThreads(threads)
	}
}

// IsTTDReached checks if the TotalTerminalDifficulty has been surpassed on the `parentHash` block.
// It depends on the parentHash already being stored in the database.
// If the parentHash is not stored in the database a UnknownAncestor error is returned.
func IsTTDReached(chain consensus.ChainHeaderReader, parentHash common.Hash, number uint64) (bool, error) {
	if chain.Config().TerminalTotalDifficulty == nil {
		return false, nil
	}
	td := chain.GetTd(parentHash, number)
	if td == nil {
		return false, consensus.ErrUnknownAncestor
	}
	return td.Cmp(chain.Config().TerminalTotalDifficulty) >= 0, nil
}
