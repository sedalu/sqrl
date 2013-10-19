package sqrl

import (
	"bytes"
	// "crypto/subtle"
	"encoding/hex"
	// "fmt"
	"testing"
)

func TestCryptoRand(t *testing.T) {
	// Test creating 64-bit cryptographic random number
	if len(cryptoRand(8)) != 8 {
		t.Fail()
	}

	// Test creating 128-bit cryptographic random number
	if len(cryptoRand(16)) != 16 {
		t.Fail()
	}

	// Test creating 256-bit cryptographic random number
	if len(cryptoRand(32)) != 32 {
		t.Fail()
	}
}

func BenchmarkCryptoRand_64bit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cryptoRand(8)
	}
}

func BenchmarkCryptoRand_128bit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cryptoRand(16)
	}
}

func BenchmarkCryptoRand_256bit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cryptoRand(32)
	}
}

func TestHashKey(t *testing.T) {
	key := []byte("hello")
	hash, _ := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

	if bytes.Compare(hashKey(key), hash) != 0 {
		t.Fail()
	}
}

func BenchmarkHashKey(b *testing.B) {
	key := []byte("hello")

	for i := 0; i < b.N; i++ {
		hashKey(key)
	}
}

func TestVerifyHash(t *testing.T) {
	hash, _ := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

	// Good case
	if !verifyHash(hash, hash[:8]) {
		t.Fail()
	}

	// Bad case
	if verifyHash(hash[1:], hash[:8]) {
		t.Fail()
	}
}

func BenchmarkVerifyHash(b *testing.B) {
	hash, _ := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

	for i := 0; i < b.N; i++ {
		verifyHash(hash, hash[:8])
	}
}

func TestVerifyKey(t *testing.T) {
	key1, key2 := []byte("hello"), []byte("world")
	hash, _ := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

	// Good case
	if verifyKey(key1, hash) {
		t.Fail()
	}

	// Bad case
	if !verifyKey(key2, hash) {
		t.Fail()
	}
}

func BenchmarkVerifyKey(b *testing.B) {
	key := []byte("hello")
	hash, _ := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

	for i := 0; i < b.N; i++ {
		verifyKey(key, hash)
	}
}

func TestXor(t *testing.T) {
	a, _ := hex.DecodeString("1111")
	b, _ := hex.DecodeString("9999")
	c, _ := hex.DecodeString("8888")

	Xor(a, b)

	if bytes.Compare(a, c) != 0 {
		t.Fail()
	}
}

func BenchmarkXor(b *testing.B) {
	bs1, bs2 := []byte("hello"), []byte("world")

	for i := 0; i < b.N; i++ {
		Xor(bs1, bs2)
	}
}
