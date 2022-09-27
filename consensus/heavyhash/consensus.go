package heavyhash

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	maxUncles                     = 2
	allowedFutureBlockTimeSeconds = int64(15)
)

var (
	errOlderBlockTime    = errors.New("timestamp older than parent")
	errInvalidDifficulty = errors.New("non-positive difficulty")
	errInvalidPoW        = errors.New("invalid proof-of-work")
	errTooManyUncles     = errors.New("too many uncles")
	errDuplicateUncle    = errors.New("duplicate uncle")
	errUncleIsAncestor   = errors.New("uncle is ancestor")
	errDanglingUncle     = errors.New("uncle's parent is not ancestor")
	// errInvalidMixDigest  = errors.New("invalid mix digest")
)

func (hh *Heavyhash) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// TODO: implement header verification that is compatible with oPoW
func (hh *Heavyhash) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	// Short circuit if the header is known, or its parent not
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	return hh.verifyHeader(chain, header, parent, false, seal, time.Now().Unix())
}

func (hh *Heavyhash) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return ethash.CalcDifficulty(chain.Config(), time, parent)
}

func (hh *Heavyhash) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	// Spawn as many workers as allowed threads
	workers := runtime.GOMAXPROCS(0)
	if len(headers) < workers {
		workers = len(headers)
	}

	// Create a task channel and spawn the verifiers
	var (
		inputs  = make(chan int)
		done    = make(chan int, workers)
		errors  = make([]error, len(headers))
		abort   = make(chan struct{})
		unixNow = time.Now().Unix()
	)
	for i := 0; i < workers; i++ {
		go func() {
			for index := range inputs {
				errors[index] = hh.verifyHeaderWorker(chain, headers, seals, index, unixNow)
				done <- index
			}
		}()
	}

	errorsOut := make(chan error, len(headers))
	go func() {
		defer close(inputs)
		var (
			in, out = 0, 0
			checked = make([]bool, len(headers))
			inputs  = inputs
		)
		for {
			select {
			case inputs <- in:
				if in++; in == len(headers) {
					// Reached end of headers. Stop sending to workers.
					inputs = nil
				}
			case index := <-done:
				for checked[index] = true; checked[out]; out++ {
					errorsOut <- errors[out]
					if out == len(headers)-1 {
						return
					}
				}
			case <-abort:
				return
			}
		}
	}()
	return abort, errorsOut
}

func (hh *Heavyhash) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
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
		if err := hh.verifyHeader(chain, uncle, ancestors[uncle.ParentHash], true, true, time.Now().Unix()); err != nil {
			return err
		}
	}
	return nil
}

func (hh *Heavyhash) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	return hh.ethash.Prepare(chain, header)
}

func (hh *Heavyhash) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header) {
	hh.ethash.Finalize(chain, header, state, txs, uncles)
}

func (hh *Heavyhash) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	return hh.ethash.FinalizeAndAssemble(chain, header, state, txs, uncles, receipts)
}

// Seal is implemented for a full mining procedure, where a nonce is added to the serialized block header pre-seal data
func (hh *Heavyhash) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	// The logic for Sealing is going to be the following
	// 1. generate a matrix from parent's hash
	// 2. get a SealHash bytes of the header
	// 3. define a routine that increments nonce until found
	var (
		header  = block.Header()
		matrix  = GetHeavyHashMatrix(header.ParentHash)
		threads = hh.threads
	)

	// Heavy hash is going to operate on the appended with PoW critical params
	// like nonce, time, and difficulty. Basically all parameters that are not included
	// in the SealHash serialization

	// TODO: decide whether a mixHash should be included
	// and if yes, what should its value be
	// Create a runner and the multiple search threads it directs
	abort := make(chan struct{})

	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		threads = 0 // Allows disabling local mining without extra logic around local/remote
	}

	var (
		pend sync.WaitGroup
		work = make(chan *types.Header)
	)
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			hh.mine(header, matrix, id, nonce, abort, work)
		}(i, 0) // TODO: nonce is 0 right now, but it can be randomized
	}
	// Wait until sealing is terminated or a nonce is found
	go func() {
		var result *types.Header
		select {
		case <-stop:
			// Outside abort, stop all miner threads
			close(abort)
		case result = <-work:
			// One of the threads found a block, abort all others
			select {
			case results <- block.WithSeal(result):
			default:
				hh.config.Log.Warn("Sealing result is not read by miner", "mode", "local", "sealhash", hh.ethash.SealHash(block.Header()))
			}
			close(abort)
			//TODO: take into account heavyhash mining config update possibility
		}
		// Wait for all miners to terminate and return the block
		pend.Wait()
	}()
	return nil
}

// Makes some sanity checks and produces a pre-seal block serialization hash
func (hh *Heavyhash) SealHash(header *types.Header) common.Hash {
	return hh.ethash.SealHash(header)
}

func (hh *Heavyhash) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return hh.ethash.APIs(chain)
}

func (hh *Heavyhash) Close() error {
	return hh.ethash.Close()
}

func (hh *Heavyhash) verifyHeader(chain consensus.ChainHeaderReader, header, parent *types.Header, uncle, seal bool, unixNow int64) error {
	// Ensure that the header's extra-data section is of a reasonable size
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}
	// Verify the header's timestamp
	if !uncle {
		if header.Time > uint64(unixNow+allowedFutureBlockTimeSeconds) {
			return consensus.ErrFutureBlock
		}
	}
	if header.Time <= parent.Time {
		return errOlderBlockTime
	}
	// Verify the block's difficulty based on its timestamp and parent's difficulty
	expected := hh.ethash.CalcDifficulty(chain, header.Time, parent)

	if expected.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v", header.Difficulty, expected)
	}
	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	// Verify the block's gas usage and (if applicable) verify the base fee.
	if !chain.Config().IsLondon(header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, expected 'nil'", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := misc.VerifyEip1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		return err
	}
	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}
	// Verify the engine specific seal securing the block
	if seal {
		if err := hh.verifySeal(header); err != nil {
			return err
		}
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyDAOHeaderExtraData(chain.Config(), header); err != nil {
		return err
	}
	if err := misc.VerifyForkHashes(chain.Config(), header, uncle); err != nil {
		return err
	}

	return nil
}

func (hh *Heavyhash) verifyHeaderWorker(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool, index int, unixNow int64) error {
	var parent *types.Header
	if index == 0 {
		parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
	} else if headers[index-1].Hash() == headers[index].ParentHash {
		parent = headers[index-1]
	}
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	return hh.verifyHeader(chain, headers[index], parent, false, seals[index], unixNow)
}

func (hh *Heavyhash) verifySeal(header *types.Header) error {
	// Ensure that we have a valid difficulty for the block
	if header.Difficulty.Sign() <= 0 {
		return errInvalidDifficulty
	}
	// Recompute the digest and PoW values
	var (
		hash   = hh.SealHash(header).Bytes()
		input  = make([]byte, 40)
		nonce  = header.Nonce
		matrix = GetHeavyHashMatrix(header.ParentHash)
		target = new(big.Int).Div(two256, header.Difficulty)
	)
	copy(input, hash)
	binary.LittleEndian.PutUint64(input[32:], nonce.Uint64())

	opowHash := heavyhash(input, matrix)
	if new(big.Int).SetBytes(opowHash.Bytes()).Cmp(target) > 0 {
		return errInvalidPoW
	}
	return nil
}

func (hh *Heavyhash) mine(header *types.Header, matrix *HeavyHashMatrix, id int, seed uint64, abort chan struct{}, found chan *types.Header) {
	// - `header` provides a DS to use for hashing with nonce appended
	// - `matrix` heavyhash matrix for the computed for the current header
	// - `id` provides an id of the mining thread
	// - `seed` gives a randomized value for the nonce to start incrementing from
	// - `abort` provides a channel to either capture abort signal from other routines or signal aborting to others
	// - `found` is used to communicate a successful work to the providing go routine
	var (
		hash   = hh.ethash.SealHash(header).Bytes()
		target = new(big.Int).Div(two256, header.Difficulty)
		input  = make([]byte, 40)
	)

	var (
		powBuffer = new(big.Int)
		nonce     = seed
	)
	copy(input, hash)
	logger := hh.config.Log.New("opow miner", id)
	logger.Debug("Started heavyhash search for new nonces", "seed", nonce)

search:
	for {
		select {
		case <-abort:
			logger.Trace("Heavyhash nonce search aborted", "attempts", nonce-seed)
			//TODO: add hashrate stats
			break search
		default:
			//TODO: add hashrate stats
			binary.LittleEndian.PutUint64(input[32:], nonce)
			opowHash := heavyhash(input, matrix)
			if powBuffer.SetBytes(opowHash.Bytes()).Cmp(target) <= 0 {
				header = types.CopyHeader(header)
				header.Nonce = types.EncodeNonce(nonce)
				select {
				case found <- header:
					logger.Trace("Heavyhash nonce found and reported", "attempts", nonce-seed, "nonce", nonce)
				case <-abort:
					logger.Trace("Heavyhash nonce found but discarded", "attempts", nonce-seed, "nonce", nonce)
				}
				break search
			}
		}
		nonce++
	}
}
