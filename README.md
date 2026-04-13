[![Readme Card](https://github-readme-stats-fast.vercel.app/api/pin/?username=cyclone-github&repo=md6-go&theme=gruvbox)](https://github.com/cyclone-github/md6-go/)
<!--
[![Go Report Card](https://goreportcard.com/badge/github.com/cyclone-github/md6-go)](https://goreportcard.com/report/github.com/cyclone-github/md6-go)
-->
[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/md6-go.svg)](https://github.com/cyclone-github/md6-go/issues)
[![License](https://img.shields.io/github/license/cyclone-github/md6-go.svg)](LICENSE)
<!--
[![GitHub release](https://img.shields.io/github/release/cyclone-github/md6-go.svg)](https://github.com/cyclone-github/md6-go/releases) [![Go Reference](https://pkg.go.dev/badge/github.com/cyclone-github/md6-go.svg)](https://pkg.go.dev/github.com/cyclone-github/md6-go)
-->

---

# MD6-Go

MD6-Go is a pure Go implementation of the MD6 cryptographic hash function, designed by Ronald L. Rivest and submitted to the NIST SHA-3 competition. This package produces bit-identical output to the original C reference implementation and follows a similar API as Go's standard `crypto/` hash packages such as [crypto/sha256](https://pkg.go.dev/crypto/sha256).

## Installation & Import

To install, run:

```bash
go get github.com/cyclone-github/md6-go
```

Then import the package in your project:

```go
import md6 "github.com/cyclone-github/md6-go"
```

## Usage

### One-Shot Hashing

```go
package main

import (
	"encoding/hex"
	"fmt"

	md6 "github.com/cyclone-github/md6-go"
)

func main() {
	// md6-256 (returns [32]byte)
	digest := md6.Sum256([]byte("hello world"))
	fmt.Println(hex.EncodeToString(digest[:]))

	// md6-512 (returns [64]byte)
	digest512 := md6.Sum512([]byte("hello world"))
	fmt.Println(hex.EncodeToString(digest512[:]))

	// any size from 1–512 bits (returns []byte)
	digest128 := md6.Sum(128, []byte("hello world"))
	fmt.Println(hex.EncodeToString(digest128))
}
```

### Streaming (hash.Hash Interface)

```go
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	md6 "github.com/cyclone-github/md6-go"
)

func main() {
	// stream multiple writes
	h := md6.New256()
	h.Write([]byte("hello"))
	h.Write([]byte(" "))
	h.Write([]byte("world"))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))

	// hash a file
	f, _ := os.Open("document.pdf")
	defer f.Close()
	h2 := md6.New256()
	io.Copy(h2, f)
	fmt.Printf("MD6-256: %x\n", h2.Sum(nil))
}
```

### Mid-Stream Sum

`Sum(nil)` does **not** modify internal state — you can call it mid-stream, continue writing, and call it again:

```go
h := md6.New256()
h.Write([]byte("hello"))
partial := h.Sum(nil)   // md6-256("hello")

h.Write([]byte(" world"))
full := h.Sum(nil)       // md6-256("hello world")
```

### Reset and Reuse

```go
h := md6.New256()
h.Write([]byte("first message"))
hash1 := h.Sum(nil)

h.Reset()

h.Write([]byte("second message"))
hash2 := h.Sum(nil)
```

### Keyed Hashing

MD6 natively supports a key (salt) of up to 64 bytes, incorporated directly into every compression call:

```go
key := []byte("my-secret-key")
h := md6.NewKeyed(256, key)
h.Write([]byte("message"))
mac := h.Sum(nil)
```

### Full Parameter Control

```go
h := md6.NewFull(
	256,              // digest size in bits (1–512)
	[]byte("key"),    // key (nil for no key, up to 64 bytes)
	64,               // L: mode parameter (0 = sequential, 64 = fully hierarchical)
	0,                // r: rounds (0 = use default: 40 + d/4)
)
```

## Overview

MD6 was designed by **Ronald L. Rivest** (the "R" in RSA) at MIT and submitted to the [NIST SHA-3 competition](https://csrc.nist.gov/projects/hash-functions/sha-3-project) in 2008. It advanced to the first round of evaluation before being withdrawn by Rivest due to concerns about provable security at reduced round counts needed for competitive performance. The MD6 specification, C reference implementation, and supporting paper are available at [(Way Back Machine) groups.csail.mit.edu/cis/md6](https://web.archive.org/web/20120321103024/http://groups.csail.mit.edu/cis/md6/).

This package is a complete rewrite in Pure Go. It was ported by studying the C reference source (`md6.h`, `md6_compress.c`, `md6_mode.c`) alongside the NIST submission paper, then implemented and tested in Go.

## Features

### Available Functions

#### Constructors

All constructors return `hash.Hash`.

- **New() hash.Hash**
  Returns an MD6-256 digest (default).

- **New128() hash.Hash**
  Returns an MD6-128 digest.

- **New224() hash.Hash**
  Returns an MD6-224 digest.

- **New256() hash.Hash**
  Returns an MD6-256 digest.

- **New384() hash.Hash**
  Returns an MD6-384 digest.

- **New512() hash.Hash**
  Returns an MD6-512 digest.

- **NewSize(bits int) hash.Hash**
  Returns an MD6 digest of the given size in bits (1–512).

- **NewKeyed(bits int, key []byte) hash.Hash**
  Returns a new keyed (salted) hash with the given digest size and key (up to 64 bytes).

- **NewFull(bits int, key []byte, L, r int) hash.Hash**
  Returns a new hash with full control over all MD6 parameters. Set `r` to 0 for the default round count.

#### One-Shot Functions

- **Sum256(data []byte) [32]byte**
  Returns an MD6-256 hash of data.

- **Sum512(data []byte) [64]byte**
  Returns an MD6-512 hash of data.

- **Sum(bits int, data []byte) []byte**
  Returns an MD6 hash of data with the given digest size in bits (1–512).

#### hash.Hash Methods

- **Write(p []byte) (int, error)**
  Absorbs data into the hash state. Always returns `len(p), nil`.

- **Sum(b []byte) []byte**
  Appends the current hash to `b` without changing internal state.

- **Reset()**
  Resets the hash to its initial state with the same parameters.

- **Size() int**
  Returns the output size in bytes.

- **BlockSize() int**
  Returns the underlying block size (512 bytes).

#### Constants

- **Size** = 32 — MD6-256 default output size in bytes
- **Size128** = 16 — MD6-128 output size in bytes
- **Size224** = 28 — MD6-224 output size in bytes
- **Size256** = 32 — MD6-256 output size in bytes
- **Size384** = 48 — MD6-384 output size in bytes
- **Size512** = 64 — MD6-512 output size in bytes
- **BlockSize** = 512 — compression block size in bytes

## Comparison to Go's stdlib "crypto/sha256"

This MD6 package closely follows the design of Go's standard `crypto/` hash packages:

- **API Parity:**
  Both use constructors that return `hash.Hash` (e.g. `sha256.New()` / `md6.New256()`), one-shot functions that return fixed-size arrays (e.g. `sha256.Sum256()` / `md6.Sum256()`), and the same `Write` / `Sum` / `Reset` interface, making the MD6 API immediately familiar to Go developers.

- **Streaming Support:**
  Just like `crypto/sha256`, data can be written incrementally via `Write()` and finalized with `Sum()`. The result is identical regardless of how the input is chunked.

- **Additional Capabilities:**
  MD6 supports features beyond standard hash packages: arbitrary digest sizes (1–512 bits) via `NewSize()` / `Sum()`, built-in keyed hashing via `NewKeyed()`, and full parameter control via `NewFull()` for tuning tree depth and round count.

## Algorithm Details

### Compression Function

Each compression call takes 89 64-bit words (712 bytes) as input and produces 16 64-bit words (128 bytes) of output:

```
Input block N (89 words):
  N[ 0..14]  Q     15 words   Constant vector (fractional bits of sqrt(6))
  N[15..22]  K      8 words   Key / salt (zero-padded)
  N[23]      U      1 word    Node ID: (level << 56) | index
  N[24]      V      1 word    Control word: (r, L, z, p, keylen, d)
  N[25..88]  B     64 words   Data payload
```

The compression loop runs `r` rounds (default `r = 40 + d/4`). Each round applies 16 steps of NLFSR computation with quadratic feedback terms, bitwise shifts, and XOR operations. The round constant `S` evolves after each round: `S = (S << 1) ^ (S >> 63) ^ (S & Smask)`.

### Tree Mode

With the default `L = 64`, MD6 operates as a 4-ary tree:

```
Level 1:  [block0] [block1] [block2] ... [blockN]     ← 512-byte input blocks
              ↓        ↓        ↓           ↓
Level 2:  [  C0  ,   C1   ,   C2   ,   C3  ]          ← 4 × 128-byte chunks per block
              ↓
Level 3:  [  ...  ]                                     ← continues upward
              ↓
Root:     [final compression with z=1]                  ← last d bits = hash output
```

Each non-root compression uses `z = 0`. The single root compression uses `z = 1`, and the final hash value is the last `d` bits of its 1024-bit output.

## Validation

All 113 tests pass. Run them with:

```bash
go test -v ./...
```

Run benchmarks with:

```bash
go test -bench=. -benchmem ./...
```

## References

- [MD6 Project Page](https://web.archive.org/web/20120321103024/http://groups.csail.mit.edu/cis/md6/) — original specification, C reference code, and paper
- [MD6: A New Cryptographic Hash Function](https://web.archive.org/web/20170812072847/https://groups.csail.mit.edu/cis/md6/submitted-2008-10-27/Supporting_Documentation/md6_report.pdf) — full NIST submission document by Ronald L. Rivest et al.
- [NIST SHA-3 Competition](https://csrc.nist.gov/projects/hash-functions/sha-3-project) — the competition MD6 was submitted to

## License

The original MD6 C reference implementation is released under the MIT License by Ronald L. Rivest. This Go port is released under the same license. See the [LICENSE](LICENSE) file for details.
