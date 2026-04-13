package md6

import (
	"encoding/binary"
	"hash"
)

/*
Pure Go implementation of Ronald L. Rivest's MD6 cryptographic hash function
https://github.com/cyclone-github/md6-go
written by cyclone

MIT License
https://github.com/cyclone-github/md6-go/blob/main/LICENSE

v0.4.13; 2026-04-13
	initial github release
	pure Go port of MD6 C reference implementation by Ronald L. Rivest
		https://groups.csail.mit.edu/cis/md6/submitted-2008-10-27/Supporting_Documentation/md6_report.pdf // dead link
		https://web.archive.org/web/20170812072847/https://groups.csail.mit.edu/cis/md6/submitted-2008-10-27/Supporting_Documentation/md6_report.pdf
	supports all digest sizes (1-512 bits), keyed hashing, tree & sequential modes
	validated bit-identical output against C MD6 source code
	code testing and comments by Cursor / Opus 4.6 High
*/

// output sizes in bytes for standard digest widths
const (
	Size    = 32 // default (md6-256)
	Size128 = 16 // md6-128
	Size224 = 28 // md6-224
	Size256 = 32 // md6-256
	Size384 = 48 // md6-384
	Size512 = 64 // md6-512
)

// md6 data block size in bytes (b·w/8 = 64·8)
const BlockSize = blockBytes

const (
	defaultL       = 64 // fully hierarchical tree mode
	maxStackHeight = 29
)

// implements hash.Hash for md6
// data is stored in byte buffers at each tree level; when a level-1 block
// is compressed, the c-word output is written as big-endian bytes into the
// next tree level, avoiding host-endian issues and mirroring the C
// reference's byte-reversal on little-endian machines
type digest struct {
	d      int // desired hash bit-length, 1 ≤ d ≤ 512
	keylen int // key length in bytes
	L      int // mode parameter (max tree height before switching to sequential)
	r      int // number of rounds

	K [keyWords]uint64 // key words, big-endian encoded

	// tree stack; B[ell] holds the partial block at level ell
	// stored as bytes in big-endian word order; level 0 is unused
	B    [maxStackHeight][blockBytes]byte
	bits [maxStackHeight]uint32 // number of bits placed in B[ell]
	iLvl [maxStackHeight]uint64 // node index within each level
	top  int                    // highest level that has received data

	bitsProcessed uint64
	finalized     bool
	hashval       [chunkBytes]byte // final hash output (before trim: c words)

	// saved initial parameters for reset
	initD      int
	initK      [keyWords]uint64
	initKeylen int
	initL      int
	initR      int
}

// constructors

// returns a md6-256 hash (default)
func New() hash.Hash { return newDigest(256, nil, defaultL, 0) }

// returns a md6-128 hash
func New128() hash.Hash { return newDigest(128, nil, defaultL, 0) }

// returns a md6-224 hash
func New224() hash.Hash { return newDigest(224, nil, defaultL, 0) }

// returns a md6-256 hash
func New256() hash.Hash { return newDigest(256, nil, defaultL, 0) }

// returns a md6-384 hash
func New384() hash.Hash { return newDigest(384, nil, defaultL, 0) }

// returns a md6-512 hash
func New512() hash.Hash { return newDigest(512, nil, defaultL, 0) }

// returns a new hash.Hash computing an md6 hash of the given size in bits (1–512)
func NewSize(bits int) hash.Hash { return newDigest(bits, nil, defaultL, 0) }

// returns a new keyed (salted) hash.Hash with the given digest size in bits and key (up to 64 bytes)
func NewKeyed(bits int, key []byte) hash.Hash {
	return newDigest(bits, key, defaultL, 0)
}

// returns a new hash.Hash with full control over all md6 parameters; set r to 0 for default round count
func NewFull(bits int, key []byte, L, r int) hash.Hash {
	return newDigest(bits, key, L, r)
}

func newDigest(d int, key []byte, L, r int) *digest {
	if d < 1 || d > 512 {
		panic("md6: digest size must be 1–512 bits")
	}
	keylen := len(key)
	if keylen > 64 {
		panic("md6: key length must be 0–64 bytes")
	}
	if L < 0 || L > 255 {
		panic("md6: L must be 0–255")
	}
	if r == 0 {
		r = defaultRounds(d, keylen)
	}
	if r < 0 || r > maxRounds {
		panic("md6: round count must be 0–255")
	}

	st := &digest{
		d:      d,
		keylen: keylen,
		L:      L,
		r:      r,
		top:    1,
	}

	if keylen > 0 {
		// pack key bytes into big-endian uint64 words, matching the C reference's memcpy + byte-reverse
		var buf [64]byte
		copy(buf[:], key)
		for i := 0; i < keyWords; i++ {
			st.K[i] = binary.BigEndian.Uint64(buf[i*8:])
		}
	}

	// SEQ mode at level 1: pre-fill with IV = 0 (the zero bytes are
	// already there from the zero value; we just mark them as occupied)
	if L == 0 {
		st.bits[1] = uint32(chunkWords * wordBits)
	}

	// save init params for reset
	st.initD = d
	st.initK = st.K
	st.initKeylen = keylen
	st.initL = L
	st.initR = r
	return st
}

// hash.Hash interface
// resets the hash to its initial state
func (st *digest) Reset() {
	d := st.initD
	K := st.initK
	kl := st.initKeylen
	L := st.initL
	r := st.initR

	*st = digest{
		d: d, keylen: kl, L: L, r: r, K: K, top: 1,
		initD: d, initK: K, initKeylen: kl, initL: L, initR: r,
	}
	if L == 0 {
		st.bits[1] = uint32(chunkWords * wordBits)
	}
}

// returns the number of bytes Sum will produce
func (st *digest) Size() int { return (st.d + 7) / 8 }

// returns the hash's underlying block size in bytes
func (st *digest) BlockSize() int { return blockBytes }

// absorbs p into the hash state, always returns len(p), nil
func (st *digest) Write(p []byte) (int, error) {
	total := len(p)
	databitlen := uint64(total) * 8
	var j uint64

	for j < databitlen {
		space := uint64(blockWords*wordBits) - uint64(st.bits[1])
		portion := databitlen - j
		if portion > space {
			portion = space
		}

		if portion > 0 {
			byteOff := st.bits[1] / 8
			copy(st.B[1][byteOff:], p[j/8:(j+portion)/8])
		}

		j += portion
		st.bits[1] += uint32(portion)
		st.bitsProcessed += portion

		if st.bits[1] == uint32(blockWords*wordBits) && j < databitlen {
			st.process(1, false)
		}
	}
	return total, nil
}

// appends the current hash to b and returns the resulting slice
func (st *digest) Sum(in []byte) []byte {
	// work on a copy so the caller can continue writing
	d0 := *st
	d0.final()
	return append(in, d0.hashval[:d0.Size()]...)
}

// mode of operation
// compresses the block at level ell and propagates upward
// if final is true, this is the finalization pass and partial blocks are compressed with padding
func (st *digest) process(ell int, final bool) {
	if !final {
		// not final: only compress if the block is full
		if st.bits[ell] < uint32(blockWords*wordBits) {
			return
		}
	} else if ell == st.top {
		// final, at the top of the stack: check early-return conditions
		// that match the C reference (see md6_mode.c md6_process)
		if ell == st.L+1 { // seq node
			if st.bits[ell] == uint32(chunkWords*wordBits) && st.iLvl[ell] > 0 {
				return
			}
		} else { // par (tree) node at top
			if ell > 1 && st.bits[ell] == uint32(chunkWords*wordBits) {
				return
			}
		}
	}
	// else: final && ell < top → always compress (push data upward)

	z := 0
	if final && ell == st.top {
		z = 1
	}

	var C [chunkWords]uint64
	st.compressBlock(&C, ell, z)

	if z == 1 {
		// final compression: store the chaining value as big-endian bytes
		for i := 0; i < chunkWords; i++ {
			binary.BigEndian.PutUint64(st.hashval[i*8:], C[i])
		}
		return
	}

	// push the c-word result to the next level
	nextLevel := ell + 1
	if nextLevel > st.L+1 {
		nextLevel = st.L + 1
	}

	// if entering SEQ mode for the first time, reserve the first c words
	// for the chaining variable (IV = 0, already zeroed)
	if nextLevel == st.L+1 && st.iLvl[nextLevel] == 0 && st.bits[nextLevel] == 0 {
		st.bits[nextLevel] = uint32(chunkWords * wordBits)
	}

	// store C as big-endian bytes at the correct offset
	off := int(st.bits[nextLevel] / 8)
	for i := 0; i < chunkWords; i++ {
		binary.BigEndian.PutUint64(st.B[nextLevel][off+i*8:], C[i])
	}
	st.bits[nextLevel] += uint32(chunkWords * wordBits)

	if nextLevel > st.top {
		st.top = nextLevel
	}

	st.process(nextLevel, final)
}

// converts B[ell] from bytes to uint64 words, runs the standard compression function, then clears B[ell]
func (st *digest) compressBlock(C *[chunkWords]uint64, ell, z int) {
	var B [blockWords]uint64
	for i := 0; i < blockWords; i++ {
		B[i] = binary.BigEndian.Uint64(st.B[ell][i*8:])
	}

	p := blockWords*wordBits - int(st.bits[ell])

	standardCompress(
		C[:], &st.K,
		ell, st.iLvl[ell],
		st.r, st.L, z, p, st.keylen, st.d,
		B[:],
	)

	st.bits[ell] = 0
	st.iLvl[ell]++
	st.B[ell] = [blockBytes]byte{}
}

// performs md6 finalization: finds the lowest level with data, processes upward to the root with z=1, then trims the output
func (st *digest) final() {
	if st.finalized {
		return
	}

	var ell int
	if st.top == 1 {
		ell = 1
	} else {
		for ell = 1; ell <= st.top; ell++ {
			if st.bits[ell] > 0 {
				break
			}
		}
	}

	st.process(ell, true)
	st.trimHashval()
	st.finalized = true
}

// extracts the last d bits of the chaining value (stored as big-endian bytes
// in st.hashval) and left-justifies them, matching the C reference's trim_hashval
func (st *digest) trimHashval() {
	fullBytes := (st.d + 7) / 8
	partialBits := st.d % 8

	// move the last fullBytes of hashval to the front
	src := chunkBytes - fullBytes
	for i := 0; i < fullBytes; i++ {
		st.hashval[i] = st.hashval[src+i]
	}
	for i := fullBytes; i < chunkBytes; i++ {
		st.hashval[i] = 0
	}

	// left-shift by (8 - partialBits) if d is not byte-aligned
	if partialBits > 0 {
		shift := uint(8 - partialBits)
		for i := 0; i < fullBytes; i++ {
			st.hashval[i] <<= shift
			if i+1 < chunkBytes {
				st.hashval[i] |= st.hashval[i+1] >> uint(partialBits)
			}
		}
	}
}

// one-shot functions
// returns the md6-256 hash of data
func Sum256(data []byte) [Size256]byte {
	var out [Size256]byte
	h := newDigest(256, nil, defaultL, 0)
	h.Write(data)
	h.final()
	copy(out[:], h.hashval[:Size256])
	return out
}

// returns the md6-512 hash of data
func Sum512(data []byte) [Size512]byte {
	var out [Size512]byte
	h := newDigest(512, nil, defaultL, 0)
	h.Write(data)
	h.final()
	copy(out[:], h.hashval[:Size512])
	return out
}

// returns the md6 hash of data with the given digest size in bits
func Sum(bits int, data []byte) []byte {
	h := newDigest(bits, nil, defaultL, 0)
	h.Write(data)
	h.final()
	out := make([]byte, h.Size())
	copy(out, h.hashval[:h.Size()])
	return out
}
