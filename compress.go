// pure Go implementation of the MD6 compression function
// based on the C reference implementation by Ronald L. Rivest (MIT License)

package md6

import "sync"

/*
Pure Go implementation of Ronald L. Rivest's MD6 cryptographic hash function
https://github.com/cyclone-github/md6
written by cyclone

MIT License
https://github.com/cyclone-github/md6/blob/main/LICENSE
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
func makeControlWord(r, L, z, p, keylen, d int) uint64 {
	return (uint64(r) << 48) |
		(uint64(L) << 40) |
		(uint64(z) << 36) |
		(uint64(p) << 20) |
		(uint64(keylen) << 12) |
		uint64(d)
}

// packs (ell, i) into a 64-bit unique node identifier U
func makeNodeID(ell int, i uint64) uint64 {
	return (uint64(ell) << 56) | i
}

// assembles the n-word compression input block N from its components
func pack(N []uint64, K *[keyWords]uint64, ell int, i uint64, r, L, z, p, keylen, d int, B []uint64) {
	copy(N[:qWords], qConst[:])
	copy(N[qWords:qWords+keyWords], K[:])
	N[qWords+keyWords] = makeNodeID(ell, i)
	N[qWords+keyWords+uWords] = makeControlWord(r, L, z, p, keylen, d)
	copy(N[qWords+keyWords+uWords+vWords:], B[:blockWords])
}

// core NLFSR compression loop with unrolled 16-step round body
// each round's 16 steps use hardcoded shift constants matching the C reference
func mainCompressionLoop(A []uint64, r int) {
	S := s0
	size := r*chunkWords + numWords
	_ = A[size-1]

	for i := numWords; i < size; i += 16 {
		// step 0: rs=10, ls=11
		x := S ^ A[i-89] ^ A[i-17] ^ (A[i-18] & A[i-21]) ^ (A[i-31] & A[i-67])
		x ^= x >> 10
		A[i] = x ^ (x << 11)

		// step 1: rs=5, ls=24
		x = S ^ A[i-88] ^ A[i-16] ^ (A[i-17] & A[i-20]) ^ (A[i-30] & A[i-66])
		x ^= x >> 5
		A[i+1] = x ^ (x << 24)

		// step 2: rs=13, ls=9
		x = S ^ A[i-87] ^ A[i-15] ^ (A[i-16] & A[i-19]) ^ (A[i-29] & A[i-65])
		x ^= x >> 13
		A[i+2] = x ^ (x << 9)

		// step 3: rs=10, ls=16
		x = S ^ A[i-86] ^ A[i-14] ^ (A[i-15] & A[i-18]) ^ (A[i-28] & A[i-64])
		x ^= x >> 10
		A[i+3] = x ^ (x << 16)

		// step 4: rs=11, ls=15
		x = S ^ A[i-85] ^ A[i-13] ^ (A[i-14] & A[i-17]) ^ (A[i-27] & A[i-63])
		x ^= x >> 11
		A[i+4] = x ^ (x << 15)

		// step 5: rs=12, ls=9
		x = S ^ A[i-84] ^ A[i-12] ^ (A[i-13] & A[i-16]) ^ (A[i-26] & A[i-62])
		x ^= x >> 12
		A[i+5] = x ^ (x << 9)

		// step 6: rs=2, ls=27
		x = S ^ A[i-83] ^ A[i-11] ^ (A[i-12] & A[i-15]) ^ (A[i-25] & A[i-61])
		x ^= x >> 2
		A[i+6] = x ^ (x << 27)

		// step 7: rs=7, ls=15
		x = S ^ A[i-82] ^ A[i-10] ^ (A[i-11] & A[i-14]) ^ (A[i-24] & A[i-60])
		x ^= x >> 7
		A[i+7] = x ^ (x << 15)

		// step 8: rs=14, ls=6
		x = S ^ A[i-81] ^ A[i-9] ^ (A[i-10] & A[i-13]) ^ (A[i-23] & A[i-59])
		x ^= x >> 14
		A[i+8] = x ^ (x << 6)

		// step 9: rs=15, ls=2
		x = S ^ A[i-80] ^ A[i-8] ^ (A[i-9] & A[i-12]) ^ (A[i-22] & A[i-58])
		x ^= x >> 15
		A[i+9] = x ^ (x << 2)

		// step 10: rs=7, ls=29
		x = S ^ A[i-79] ^ A[i-7] ^ (A[i-8] & A[i-11]) ^ (A[i-21] & A[i-57])
		x ^= x >> 7
		A[i+10] = x ^ (x << 29)

		// step 11: rs=13, ls=8
		x = S ^ A[i-78] ^ A[i-6] ^ (A[i-7] & A[i-10]) ^ (A[i-20] & A[i-56])
		x ^= x >> 13
		A[i+11] = x ^ (x << 8)

		// step 12: rs=11, ls=15
		x = S ^ A[i-77] ^ A[i-5] ^ (A[i-6] & A[i-9]) ^ (A[i-19] & A[i-55])
		x ^= x >> 11
		A[i+12] = x ^ (x << 15)

		// step 13: rs=7, ls=5
		x = S ^ A[i-76] ^ A[i-4] ^ (A[i-5] & A[i-8]) ^ (A[i-18] & A[i-54])
		x ^= x >> 7
		A[i+13] = x ^ (x << 5)

		// step 14: rs=6, ls=31
		x = S ^ A[i-75] ^ A[i-3] ^ (A[i-4] & A[i-7]) ^ (A[i-17] & A[i-53])
		x ^= x >> 6
		A[i+14] = x ^ (x << 31)

		// step 15: rs=12, ls=9
		x = S ^ A[i-74] ^ A[i-2] ^ (A[i-3] & A[i-6]) ^ (A[i-16] & A[i-52])
		x ^= x >> 12
		A[i+15] = x ^ (x << 9)

		S = (S << 1) ^ (S >> 63) ^ (S & smask)
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
