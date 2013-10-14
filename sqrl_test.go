package sqrl

import (
	"bytes"
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
	hash, _ := hex.DecodeString("0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

	if bytes.Compare(hashKey(key), hash) == 0 {
		t.Fail()
	}
}

func BenchmarkHashKey(b *testing.B) {
	key := []byte("hello")

	for i := 0; i < b.N; i++ {
		hashKey(key)
	}
}