// pure Go implementation of the MD6 compression function
// based on the C reference implementation by Ronald L. Rivest (MIT License)

package md6

import "sync"

/*
Pure Go implementation of Ronald L. Rivest's MD6 cryptographic hash function
https://github.com/cyclone-github/md6-go
written by cyclone

MIT License
https://github.com/cyclone-github/md6-go/blob/main/LICENSE
*/

// md6 word and block geometry (w=64 standard configuration)
const (
	wordBits   = 64 // w: bits per word
	numWords   = 89 // n: compression input size in words
	chunkWords = 16 // c: compression output size in words
	blockWords = 64 // b: data words per compression block
	qWords     = 15 // q: number of Q constant words
	keyWords   = 8  // k: key words per block
	uWords     = 1  // u: unique node ID words
	vWords     = 1  // v: control word words
	maxRounds  = 255

	blockBytes = blockWords * (wordBits / 8) // 512
	chunkBytes = chunkWords * (wordBits / 8) // 128
)

// tap positions for the feedback shift register (n=89)
const (
	t0 = 17
	t1 = 18
	t2 = 21
	t3 = 31
	t4 = 67
	t5 = 89 // = numWords
)

// round constant seed and mask
const (
	s0    uint64 = 0x0123456789abcdef
	smask uint64 = 0x7311c2812425cfa0
)

// first 960 bits of the fractional part of sqrt(6)
var qConst = [qWords]uint64{
	0x7311c2812425cfa0,
	0x6432286434aac8e7,
	0xb60450e9ef68b7c1,
	0xe8fb23908d9f06f1,
	0xdd2e76cba691e5bf,
	0x0cd0d63b2c30bc41,
	0x1f8ccf6823058f8a,
	0x54e5ed5b88e3775d,
	0x4ad12aae0a6d6031,
	0x3e7f16bb88222e0d,
	0x8af8671d3fb50c2c,
	0x995ad1178bd25c31,
	0xc878c1dd04c4b633,
	0x3b72066c7a1552ac,
	0x0d6f3522631effcb,
}

// per-step shift amounts (right-shift, left-shift) for w=64
// 16 steps per round, matching the C reference's unrolled loop body macros
var shifts = [chunkWords][2]uint{
	{10, 11}, {5, 24}, {13, 9}, {10, 16},
	{11, 15}, {12, 9}, {2, 27}, {7, 15},
	{14, 6}, {15, 2}, {7, 29}, {13, 8},
	{11, 15}, {7, 5}, {6, 31}, {12, 9},
}

// returns the default number of rounds for the given digest bit-length d and key byte-length keylen
// formula: r = 40 + floor(d/4); if keylen > 0 then r = max(80, r)
func defaultRounds(d, keylen int) int {
	r := 40 + d/4
	if keylen > 0 && r < 80 {
		r = 80
	}
	return r
}

// packs (r, L, z, p, keylen, d) into a 64-bit control word V
//
//	bits 63–60: reserved (0)
//	bits 59–48: r  (12 bits)
//	bits 47–40: L  (8 bits)
//	bits 39–36: z  (4 bits)
//	bits 35–20: p  (16 bits)
//	bits 19–12: keylen (8 bits)
//	bits 11–0:  d  (12 bits)
func makeControlWord(r, L, z, p, keylen, d int) uint64 {
	return (uint64(r) << 48) |
		(uint64(L) << 40) |
		(uint64(z) << 36) |
		(uint64(p) << 20) |
		(uint64(keylen) << 12) |
		uint64(d)
}

// packs (ell, i) into a 64-bit unique node identifier U
//
//	bits 63–56: ell (level number, 8 bits)
//	bits 55–0:  i   (index within level)
func makeNodeID(ell int, i uint64) uint64 {
	return (uint64(ell) << 56) | i
}

// assembles the n-word compression input block N from its components
//
//	N[0..14]  = Q   (constant vector)
//	N[15..22] = K   (key / salt)
//	N[23]     = U   (node ID)
//	N[24]     = V   (control word)
//	N[25..88] = B   (data payload)
func pack(N []uint64, K *[keyWords]uint64, ell int, i uint64, r, L, z, p, keylen, d int, B []uint64) {
	ni := 0
	for j := 0; j < qWords; j++ {
		N[ni] = qConst[j]
		ni++
	}
	for j := 0; j < keyWords; j++ {
		N[ni] = K[j]
		ni++
	}
	N[ni] = makeNodeID(ell, i)
	ni += uWords
	N[ni] = makeControlWord(r, L, z, p, keylen, d)
	ni += vWords
	copy(N[ni:ni+blockWords], B[:blockWords])
}

// core NLFSR compression loop, fills A[n .. r*c+n-1] from A[0..n-1]
func mainCompressionLoop(A []uint64, r int) {
	S := s0
	idx := numWords
	for j := 0; j < r*chunkWords; j += chunkWords {
		for step := 0; step < chunkWords; step++ {
			x := S
			x ^= A[idx+step-t5]
			x ^= A[idx+step-t0]
			x ^= A[idx+step-t1] & A[idx+step-t2]
			x ^= A[idx+step-t3] & A[idx+step-t4]
			x ^= x >> shifts[step][0]
			A[idx+step] = x ^ (x << shifts[step][1])
		}
		S = (S << 1) ^ (S >> (wordBits - 1)) ^ (S & smask)
		idx += chunkWords
	}
}

// recycled working array for the compression function
// max size is maxRounds*chunkWords + numWords = 255*16+89 = 4169 words
const aPoolSize = maxRounds*chunkWords + numWords

var aPool = sync.Pool{
	New: func() any {
		buf := make([]uint64, aPoolSize)
		return &buf
	},
}

// runs the md6 compression function on n-word input N, producing c-word output in C
func compress(C []uint64, N []uint64, r int) {
	size := r*chunkWords + numWords
	bp := aPool.Get().(*[]uint64)
	A := (*bp)[:size]

	copy(A, N[:numWords])
	// positions A[n..] are written sequentially by the loop before being
	// read, so stale pool data beyond n is harmless and need not be zeroed
	mainCompressionLoop(A, r)
	copy(C[:chunkWords], A[size-chunkWords:])

	aPool.Put(bp)
}

// packs input components into N, then compresses
func standardCompress(C []uint64, K *[keyWords]uint64, ell int, i uint64, r, L, z, p, keylen, d int, B []uint64) {
	var N [numWords]uint64
	pack(N[:], K, ell, i, r, L, z, p, keylen, d, B)
	compress(C, N[:], r)
}
