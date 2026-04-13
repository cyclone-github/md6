package md6

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"
)

/*
Pure Go implementation of Ronald L. Rivest's MD6 cryptographic hash function
https://github.com/cyclone-github/md6
written by cyclone

MIT License
https://github.com/cyclone-github/md6/blob/main/LICENSE
*/

// test vectors from the C reference implementation

type vector struct {
	label  string
	d      int    // digest bits
	input  []byte // message
	expect string // lowercase hex
}

var vectors = []vector{
	// ---- empty string ----
	{"empty-128", 128, nil, "032f75b3ca02a393196a818328bd32e8"},
	{"empty-160", 160, nil, "f325ee93c54cfaacd7b9007e1cf8904680993b18"},
	{"empty-224", 224, nil, "d2091aa2ad17f38c51ade2697f24cafc3894c617c77ffe10fdc7abcb"},
	{"empty-256", 256, nil, "bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca"},
	{"empty-384", 384, nil, "b0bafffceebe856c1eff7e1ba2f539693f828b532ebf60ae9c16cbc3499020401b942ac25b310b2227b2954ccacc2f1f"},
	{"empty-512", 512, nil, "6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0f8e0c0"},

	// ---- "abc" ----
	{"abc-128", 128, []byte("abc"), "8db50d79cf42fe7d1807ebaa15329c61"},
	{"abc-160", 160, []byte("abc"), "b5c2d6a7ce6be0c18c9a38b17a0db705c81ab6b5"},
	{"abc-224", 224, []byte("abc"), "510c30e4202a5cdd8a4f2ae9beebb6f5988128897937615d52e6d228"},
	{"abc-256", 256, []byte("abc"), "230637d4e6845cf0d092b558e87625f03881dd53a7439da34cf3b94ed0d8b2c5"},
	{"abc-384", 384, []byte("abc"), "e2c6d31dd8872cbd5a1207481cdac581054d13a4d4fe6854331cd8cf3e7cbafbaddd6e2517972b8ff57cdc4806d09190"},
	{"abc-512", 512, []byte("abc"), "00918245271e377a7ffb202b90f3bda5477d8feab12d8a3a8994ebc55fe6e74ca8341520032eeea3fdef892f2882378f636212af4b2683ccf80bf025b7d9b457"},

	// ---- "The quick brown fox jumps over the lazy dog" ----
	{"fox-128", 128, []byte("The quick brown fox jumps over the lazy dog"), "7b428f5ec47e0174faf31dc7c89590c6"},
	{"fox-160", 160, []byte("The quick brown fox jumps over the lazy dog"), "89c6f1da416b8a09a3fd670f091aeddb7c7c8af6"},
	{"fox-224", 224, []byte("The quick brown fox jumps over the lazy dog"), "188528b2add27528c514474ce6150a44df9498f8845a620fdf177295"},
	{"fox-256", 256, []byte("The quick brown fox jumps over the lazy dog"), "977592608c45c9923340338450fdcccc21a68888e1e6350e133c5186cd9736ee"},
	{"fox-384", 384, []byte("The quick brown fox jumps over the lazy dog"), "d850fdde986e16df19d65c50788afd0a8953914a4bc65831f5283c3016b79ddfa4a0bc00694e472f4a0bed7da601bb90"},
	{"fox-512", 512, []byte("The quick brown fox jumps over the lazy dog"), "dcba0c6593fbd83a0f5f148588baa79530579c1f5e7f19d500fe282d137bff465106f25c9f0619b4082a730683d5f58311c0c1913068e91b0ebdf9ace3ff5b9e"},

	// ---- 1000 × 'a' ----
	{"1000a-128", 128, bytes.Repeat([]byte("a"), 1000), "8f67b4e518ef8abfb1b72e5991cd1b30"},
	{"1000a-160", 160, bytes.Repeat([]byte("a"), 1000), "21f09753b1d6cccbf6c1c6a4e759654cd3d062fe"},
	{"1000a-224", 224, bytes.Repeat([]byte("a"), 1000), "4d7891b9a33cbc6eaf2f94447d2cb481354f429d06d04fdf05ef94ff"},
	{"1000a-256", 256, bytes.Repeat([]byte("a"), 1000), "ff7c492a5b92f45bbf62acc81738e8aae8d1cc87a2be9173da0630b107815d76"},
	{"1000a-384", 384, bytes.Repeat([]byte("a"), 1000), "5c4e6159f84fb856e7bb88c49c6b750fdd3ea4bffbfa10967378501acd8865669f61b8c0b0f6d19c310cd619093e4774"},
	{"1000a-512", 512, bytes.Repeat([]byte("a"), 1000), "4c74e18466da05ac0050f33634088059598297b87022ce22e6b7adcf257b1c378d8cc53c121bb02fec3678b2fd53ad625cea17a202621aa97022efaa1acd1fde"},

	// ---- 8192 sequential bytes ----
	{"8192seq-128", 128, seqBytes(8192), "edaf821142ee4c45fef33d2600d7e158"},
	{"8192seq-160", 160, seqBytes(8192), "ee461f521da232da32d887711c3d85004fd23371"},
	{"8192seq-224", 224, seqBytes(8192), "c23eba42a7494fb9bc2aa8146f2476ca2114d6deef5280faa8aa53e4"},
	{"8192seq-256", 256, seqBytes(8192), "2a40338156df221b18b20e4003f51f61284cacd01935e9e87414e6ae40a6bd25"},
	{"8192seq-384", 384, seqBytes(8192), "15831c087ab689f4e1370b2618129aa5a17fb29fe4cc5300b0e53a75f2f7c9f73fb8d29817025ea1b83801a1b95bbb0c"},
	{"8192seq-512", 512, seqBytes(8192), "a9d0a1262f13414b9d48448e1e534cd47cbd40ffffdb8dc882619c747a284a462a7ff4fbb27180a390d182801a9722b3f1c7d04ef5ce90bb553446c286b97ccb"},

	// ---- Odd digest sizes ----
	{"empty-1", 1, nil, "00"},
	{"empty-8", 8, nil, "3e"},
	{"empty-17", 17, nil, "9a0900"},
	{"empty-100", 100, nil, "3e2b7d765cc7cef3bda7228790"},
	{"abc-1", 1, []byte("abc"), "00"},
	{"abc-8", 8, []byte("abc"), "e8"},
	{"abc-100", 100, []byte("abc"), "13c4cfbd2a58de21ae166c6160"},
}

func seqBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i & 0xff)
	}
	return b
}

// validates all known-good vectors from the C reference
func TestVectors(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.label, func(t *testing.T) {
			h := NewSize(v.d).(*digest)
			if v.input != nil {
				h.Write(v.input)
			}
			got := hex.EncodeToString(h.Sum(nil))
			if got != v.expect {
				t.Fatalf("got  %s\nwant %s", got, v.expect)
			}
		})
	}
}

// validates the four vectors from md6_examples.txt
func TestExampleFile(t *testing.T) {
	cases := []struct {
		name   string
		d      int
		input  string
		expect string
	}{
		{"MD6-256 fox", 256, "The quick brown fox jumps over the lazy dog", "977592608c45c9923340338450fdcccc21a68888e1e6350e133c5186cd9736ee"},
		{"MD6-128 empty", 128, "", "032f75b3ca02a393196a818328bd32e8"},
		{"MD6-256 empty", 256, "", "bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca"},
		{"MD6-512 empty", 512, "", "6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0f8e0c0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := NewSize(c.d)
			h.Write([]byte(c.input))
			got := hex.EncodeToString(h.Sum(nil))
			if got != c.expect {
				t.Fatalf("got  %s\nwant %s", got, c.expect)
			}
		})
	}
}

// verifies that repeated small Write calls produce the same result as a single Write
func TestStreaming(t *testing.T) {
	sizes := []int{128, 256, 512}
	inputs := []struct {
		name string
		data []byte
	}{
		{"abc", []byte("abc")},
		{"1000a", bytes.Repeat([]byte("a"), 1000)},
		{"8192seq", seqBytes(8192)},
	}
	chunks := []int{1, 7, 13, 64, 127, 255, 512, 1024}

	for _, sz := range sizes {
		for _, inp := range inputs {
			// reference: single write
			ref := NewSize(sz)
			ref.Write(inp.data)
			want := hex.EncodeToString(ref.Sum(nil))

			for _, cs := range chunks {
				name := fmt.Sprintf("d%d/%s/chunk%d", sz, inp.name, cs)
				t.Run(name, func(t *testing.T) {
					h := NewSize(sz)
					for off := 0; off < len(inp.data); off += cs {
						end := off + cs
						if end > len(inp.data) {
							end = len(inp.data)
						}
						h.Write(inp.data[off:end])
					}
					got := hex.EncodeToString(h.Sum(nil))
					if got != want {
						t.Fatalf("chunk=%d: got  %s\n              want %s", cs, got, want)
					}
				})
			}
		}
	}
}

// verifies that calling Sum does not change the internal state and that further writes still work
func TestSumDoesNotMutate(t *testing.T) {
	h := New256()
	h.Write([]byte("hello"))
	sum1 := h.Sum(nil)

	// write more data after Sum
	h.Write([]byte(" world"))
	sum2 := h.Sum(nil)

	// sum1 should be md6-256("hello")
	ref1 := Sum256([]byte("hello"))
	want1 := hex.EncodeToString(ref1[:])
	got1 := hex.EncodeToString(sum1)
	if got1 != want1 {
		t.Fatalf("after first Sum: got %s, want %s", got1, want1)
	}

	// sum2 should be md6-256("hello world")
	ref2 := Sum256([]byte("hello world"))
	want2 := hex.EncodeToString(ref2[:])
	got2 := hex.EncodeToString(sum2)
	if got2 != want2 {
		t.Fatalf("after second Sum: got %s, want %s", got2, want2)
	}
}

// verifies that Reset brings the hash back to a clean state
func TestReset(t *testing.T) {
	h := New256()
	h.Write([]byte("garbage data that will be discarded"))
	h.Reset()
	h.Write([]byte("abc"))
	got := hex.EncodeToString(h.Sum(nil))
	want := "230637d4e6845cf0d092b558e87625f03881dd53a7439da34cf3b94ed0d8b2c5"
	if got != want {
		t.Fatalf("after Reset: got %s, want %s", got, want)
	}
}

// checks that named constructors produce correct sizes
func TestConstructors(t *testing.T) {
	cases := []struct {
		name string
		h    hash.Hash
		size int
	}{
		{"New", New(), Size256},
		{"New128", New128(), Size128},
		{"New224", New224(), Size224},
		{"New256", New256(), Size256},
		{"New384", New384(), Size384},
		{"New512", New512(), Size512},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.h.Size() != c.size {
				t.Fatalf("Size() = %d, want %d", c.h.Size(), c.size)
			}
			if c.h.BlockSize() != BlockSize {
				t.Fatalf("BlockSize() = %d, want %d", c.h.BlockSize(), BlockSize)
			}
			sum := c.h.Sum(nil)
			if len(sum) != c.size {
				t.Fatalf("Sum len = %d, want %d", len(sum), c.size)
			}
		})
	}
}

// tests the one-shot Sum256 function
func TestSum256Func(t *testing.T) {
	got := Sum256([]byte("abc"))
	want := "230637d4e6845cf0d092b558e87625f03881dd53a7439da34cf3b94ed0d8b2c5"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("Sum256(abc) = %x, want %s", got, want)
	}
}

// tests the one-shot Sum512 function
func TestSum512Func(t *testing.T) {
	got := Sum512(nil)
	want := "6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0f8e0c0"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("Sum512(\"\") = %x, want %s", got, want)
	}
}

// tests the generic Sum function
func TestSumFunc(t *testing.T) {
	got := Sum(128, nil)
	want := "032f75b3ca02a393196a818328bd32e8"
	if hex.EncodeToString(got) != want {
		t.Fatalf("Sum(128, \"\") = %x, want %s", got, want)
	}
}

// tests hashing a message that spans multiple tree levels
func TestLargeMessage(t *testing.T) {
	data := make([]byte, 100000)
	for i := range data {
		data[i] = byte(i & 0xff)
	}
	// compute via streaming in 1-byte and 4096-byte chunks; must match
	h1 := New256()
	for i := range data {
		h1.Write(data[i : i+1])
	}
	sum1 := h1.Sum(nil)

	h2 := New256()
	for off := 0; off < len(data); off += 4096 {
		end := off + 4096
		if end > len(data) {
			end = len(data)
		}
		h2.Write(data[off:end])
	}
	sum2 := h2.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Fatalf("100KB streaming mismatch:\n  1-byte: %x\n  4096:   %x", sum1, sum2)
	}

	// also match single-shot
	h3 := New256()
	h3.Write(data)
	sum3 := h3.Sum(nil)
	if !bytes.Equal(sum1, sum3) {
		t.Fatalf("100KB single-shot mismatch:\n  1-byte: %x\n  single: %x", sum1, sum3)
	}
}

// validates the round-count formula
func TestDefaultRounds(t *testing.T) {
	if r := defaultRounds(256, 0); r != 104 {
		t.Fatalf("defaultRounds(256,0) = %d, want 104", r)
	}
	if r := defaultRounds(512, 0); r != 168 {
		t.Fatalf("defaultRounds(512,0) = %d, want 168", r)
	}
	if r := defaultRounds(128, 0); r != 72 {
		t.Fatalf("defaultRounds(128,0) = %d, want 72", r)
	}
	// with key: r = max(80, 40+d/4)
	if r := defaultRounds(128, 8); r != 80 {
		t.Fatalf("defaultRounds(128,8) = %d, want 80", r)
	}
	if r := defaultRounds(256, 8); r != 104 {
		t.Fatalf("defaultRounds(256,8) = %d, want 104", r)
	}
}

// checks that invalid sizes panic
func TestNewSizePanics(t *testing.T) {
	for _, d := range []int{0, -1, 513, 1024} {
		t.Run(fmt.Sprintf("d=%d", d), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("NewSize(%d) did not panic", d)
				}
			}()
			NewSize(d)
		})
	}
}

// verifies that Write always returns (len(p), nil)
func TestWriteReturn(t *testing.T) {
	h := New256()
	data := []byte("test data")
	n, err := h.Write(data)
	if n != len(data) || err != nil {
		t.Fatalf("Write returned (%d, %v), want (%d, nil)", n, err, len(data))
	}
}

// benchmarks

func benchmarkSize(b *testing.B, size int, msgLen int) {
	data := make([]byte, msgLen)
	for i := range data {
		data[i] = byte(i)
	}
	b.SetBytes(int64(msgLen))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := NewSize(size)
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkMD6_256_8(b *testing.B)   { benchmarkSize(b, 256, 8) }
func BenchmarkMD6_256_64(b *testing.B)  { benchmarkSize(b, 256, 64) }
func BenchmarkMD6_256_512(b *testing.B) { benchmarkSize(b, 256, 512) }
func BenchmarkMD6_256_1K(b *testing.B)  { benchmarkSize(b, 256, 1024) }
func BenchmarkMD6_256_8K(b *testing.B)  { benchmarkSize(b, 256, 8192) }
func BenchmarkMD6_256_1M(b *testing.B)  { benchmarkSize(b, 256, 1<<20) }
func BenchmarkMD6_512_8(b *testing.B)   { benchmarkSize(b, 512, 8) }
func BenchmarkMD6_512_64(b *testing.B)  { benchmarkSize(b, 512, 64) }
func BenchmarkMD6_512_512(b *testing.B) { benchmarkSize(b, 512, 512) }
func BenchmarkMD6_512_1K(b *testing.B)  { benchmarkSize(b, 512, 1024) }
func BenchmarkMD6_512_8K(b *testing.B)  { benchmarkSize(b, 512, 8192) }
func BenchmarkMD6_512_1M(b *testing.B)  { benchmarkSize(b, 512, 1<<20) }
func BenchmarkMD6_128_512(b *testing.B) { benchmarkSize(b, 128, 512) }
func BenchmarkMD6_128_8K(b *testing.B)  { benchmarkSize(b, 128, 8192) }

func BenchmarkSum256(b *testing.B) {
	data := make([]byte, 512)
	b.SetBytes(512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256(data)
	}
}

// simulates hashgen pattern: one-shot md6-512 on short passwords
func BenchmarkSum512_Short(b *testing.B) {
	data := []byte("password123")
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum512(data)
	}
}

// simulates hashgen pattern: one-shot md6-256 on short passwords
func BenchmarkSum256_Short(b *testing.B) {
	data := []byte("password123")
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256(data)
	}
}

// simulates streaming with reuse via Reset
func BenchmarkMD6_512_Reuse(b *testing.B) {
	data := []byte("password123")
	h := New512()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkSum_Generic_512(b *testing.B) {
	data := []byte("password123")
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(512, data)
	}
}
