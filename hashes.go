// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package keccak

import "hash"

// NewLegacyKeccak256 creates a new Keccak-256 hash.
//
// Only use this function if you require compatibility with an existing cryptosystem
// that uses non-standard padding. All other users should use [crypto/sha3.New256] instead.
func NewLegacyKeccak256() hash.Hash {
	return &state{rate: rateK512, outputLen: 32, dsbyte: dsbyteKeccak}
}

// NewLegacyKeccak512 creates a new Keccak-512 hash.
//
// Only use this function if you require compatibility with an existing cryptosystem
// that uses non-standard padding. All other users should use [crypto/sha3.New512] instead.
func NewLegacyKeccak512() hash.Hash {
	return &state{rate: rateK1024, outputLen: 64, dsbyte: dsbyteKeccak}
}
