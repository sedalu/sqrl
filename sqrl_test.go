package sqrl

import (
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

func BenchmarkCryptoRand_8(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cryptoRand(8)
	}
}

func BenchmarkCryptoRand_16(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cryptoRand(16)
	}
}

func BenchmarkCryptoRand_32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cryptoRand(32)
	}
}