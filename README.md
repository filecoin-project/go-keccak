# go-keccak

Legacy Keccak-256 and Keccak-512 hash functions with amd64 assembly-optimized
permutation, vendored from [`golang.org/x/crypto/sha3`](https://pkg.go.dev/golang.org/x/crypto/sha3)
at **v0.43.0**.

## Why?

Starting with `golang.org/x/crypto` **v0.44.0**, the `sha3` package removed its
assembly-optimized Keccak-f[1600] permutation in favor of Go 1.24's standard
library `crypto/sha3`. However, the standard library does not provide the legacy
Keccak functions (`NewLegacyKeccak256`, `NewLegacyKeccak512`) with the assembly
fast path — the legacy functions now always use the pure-Go permutation,
resulting in a performance regression.

The legacy Keccak hash (using domain separator `0x01` instead of SHA-3's `0x06`)
is used pervasively in Ethereum and Filecoin for address derivation, state
hashing, and other protocol operations. This package preserves the fast
assembly-optimized path for these functions.

See also: [go-ethereum#33323](https://github.com/ethereum/go-ethereum/pull/33323)
which vendors the same upstream code for the same reason.

## Usage

```go
import "github.com/filecoin-project/go-keccak"

h := keccak.NewLegacyKeccak256()
h.Write(data)
digest := h.Sum(nil)
```

## API

- `NewLegacyKeccak256() hash.Hash` — Keccak-256 (32-byte output)
- `NewLegacyKeccak512() hash.Hash` — Keccak-512 (64-byte output)

## Performance

On amd64, this package uses the assembly-optimized Keccak-f[1600] permutation
from `golang.org/x/crypto/sha3@v0.43.0`. On all other architectures, it falls
back to the pure-Go implementation (same as upstream behavior).

## Source

All cryptographic code is vendored unmodified from
[`golang.org/x/crypto/sha3`](https://github.com/golang/crypto/tree/v0.43.0/sha3)
at tag `v0.43.0`. The only changes are:

- Package renamed from `sha3` to `keccak`
- API trimmed to legacy Keccak functions only (SHA-3, SHAKE, cSHAKE removed)
- `golang.org/x/sys/cpu` dependency removed (big-endian detection inlined)
- s390x assembly not included (pure-Go fallback used on that platform)

## License

BSD 3-Clause, same as the upstream `golang.org/x/crypto` package.
See [LICENSE](LICENSE).
