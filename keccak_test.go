// Copyright 2024 The go-keccak Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keccak

import (
	"encoding/hex"
	"hash"
	"testing"
)

// Test vectors from the Keccak reference implementation.
// These use the pre-standardization Keccak padding (domain separator 0x01),
// NOT the SHA-3 padding (domain separator 0x06).

func TestKeccak256Empty(t *testing.T) {
	// Keccak-256 of empty input
	expected := "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	h := NewLegacyKeccak256()
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		t.Errorf("Keccak256('') = %s, want %s", got, expected)
	}
}

func TestKeccak256ABC(t *testing.T) {
	// Keccak-256 of "abc"
	expected := "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
	h := NewLegacyKeccak256()
	h.Write([]byte("abc"))
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		t.Errorf("Keccak256('abc') = %s, want %s", got, expected)
	}
}

func TestKeccak512Empty(t *testing.T) {
	// Keccak-512 of empty input
	expected := "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"
	h := NewLegacyKeccak512()
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		t.Errorf("Keccak512('') = %s, want %s", got, expected)
	}
}

func TestKeccak512ABC(t *testing.T) {
	// Keccak-512 of "abc"
	expected := "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96"
	h := NewLegacyKeccak512()
	h.Write([]byte("abc"))
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		t.Errorf("Keccak512('abc') = %s, want %s", got, expected)
	}
}

func TestKeccak256Incremental(t *testing.T) {
	// Writing in chunks produces the same result as writing all at once.
	msg := []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
	expected := singleShotHash(NewLegacyKeccak256, msg)

	h := NewLegacyKeccak256()
	for _, b := range msg {
		h.Write([]byte{b})
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		t.Errorf("incremental Keccak256 = %s, want %s", got, expected)
	}
}

func TestKeccak256Reset(t *testing.T) {
	h := NewLegacyKeccak256()
	h.Write([]byte("garbage"))
	h.Reset()

	expected := singleShotHash(NewLegacyKeccak256, nil)
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		t.Errorf("after Reset, Keccak256 = %s, want %s", got, expected)
	}
}

func TestKeccak256SumDoesNotMutate(t *testing.T) {
	// Sum should not change the internal state; calling Sum twice
	// produces the same result.
	h := NewLegacyKeccak256()
	h.Write([]byte("hello"))
	sum1 := hex.EncodeToString(h.Sum(nil))
	sum2 := hex.EncodeToString(h.Sum(nil))
	if sum1 != sum2 {
		t.Errorf("Sum mutated state: %s != %s", sum1, sum2)
	}
}

func TestKeccak256Size(t *testing.T) {
	h := NewLegacyKeccak256()
	if h.Size() != 32 {
		t.Errorf("Size() = %d, want 32", h.Size())
	}
}

func TestKeccak512Size(t *testing.T) {
	h := NewLegacyKeccak512()
	if h.Size() != 64 {
		t.Errorf("Size() = %d, want 64", h.Size())
	}
}

func TestKeccak256BlockSize(t *testing.T) {
	h := NewLegacyKeccak256()
	if h.BlockSize() != rateK512 {
		t.Errorf("BlockSize() = %d, want %d", h.BlockSize(), rateK512)
	}
}

func TestKeccak256MarshalUnmarshal(t *testing.T) {
	h1 := NewLegacyKeccak256()
	h1.Write([]byte("hello"))

	// Marshal
	s := h1.(*state)
	data, err := s.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal into a fresh hasher
	h2 := NewLegacyKeccak256()
	s2 := h2.(*state)
	if err := s2.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}

	// Both should produce the same final hash
	h1.Write([]byte(" world"))
	h2.Write([]byte(" world"))
	if hex.EncodeToString(h1.Sum(nil)) != hex.EncodeToString(h2.Sum(nil)) {
		t.Error("marshaled/unmarshaled hash produced different result")
	}
}

func singleShotHash(newFunc func() hash.Hash, data []byte) string {
	h := newFunc()
	if data != nil {
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Ethereum-specific test: Keccak-256 of an Ethereum address derivation pattern.
func TestKeccak256EthereumAddress(t *testing.T) {
	// keccak256("") is used as Ethereum's empty account code hash
	h := NewLegacyKeccak256()
	sum := h.Sum(nil)
	expected := "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	got := hex.EncodeToString(sum)
	if got != expected {
		t.Errorf("Ethereum empty codehash = %s, want %s", got, expected)
	}
}

func BenchmarkKeccak256_32(b *testing.B) {
	benchmarkHash(b, NewLegacyKeccak256, 32)
}

func BenchmarkKeccak256_1K(b *testing.B) {
	benchmarkHash(b, NewLegacyKeccak256, 1024)
}

func BenchmarkKeccak256_8K(b *testing.B) {
	benchmarkHash(b, NewLegacyKeccak256, 8192)
}

func benchmarkHash(b *testing.B, newFunc func() hash.Hash, size int) {
	b.SetBytes(int64(size))
	data := make([]byte, size)
	h := newFunc()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(data)
		h.Sum(nil)
	}
}
