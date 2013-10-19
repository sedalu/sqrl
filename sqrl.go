/*
	The sqrl package implements the Secure QR Login (SQRL) protocal for both server and client. See https://www.grc.com/sqrl/sqrl.htm for more information regarding SQRL.

	!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!
	!!       EXPERIMENTAL CODE - USE AT YOUR OWN RISK!       !!
	!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!

	The MIT License (MIT)

	Copyright (c) 2013 sedalu

	Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package sqrl

import (
	"bytes"
	"code.google.com/p/go.crypto/scrypt"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/dustyburwell/ed25519"
	"net/http"
	// "net/url"
	// "strconv"
	"strings"
)

type Version int

const (
	SQRL1 Version = iota
)

type Option int

const (
	None Option = 1 << iota - 1
	Enforce
)

const keyLen   int = 32
const checkLen int = 16
const saltLen  int = 8

// Key stores a 256-bit cryptographic key
type Key [keyLen]byte

type Client struct {
	
}

// Authenticate
func (this *Client) Authenticate(id *Identity, password, siteUrl string, options Option) (request *http.Request, err error) {
	// Get the domain.
	domain := "example.com"

	// Get the private key for the domain.
	key, err := id.GenerateKey(domain, password)

	if err != nil {
		return
	}

	// Build the response URL.
	// 1. Challenge URL without the scheme
	url := strings.SplitN(siteUrl, "://", 2)[1]

	// 2. Add sqrlver
	url += fmt.Sprintf("&%s=%s", "sqrlver", SQRL1)

	// 3. Add sqrlopt
	if options != None {
		var opts []string

		if options & Enforce == Enforce {
			opts = append(opts, "enforce")
		}

		url += fmt.Sprintf("&%s=%s", "sqrlopt", strings.Join(opts, ","))
	}

	// 4. Add sqrlkey
	sqrlkey := base64.URLEncoding.EncodeToString(key.PublicKey[:])
	sqrlkey = strings.TrimRight(sqrlkey, "=")
	url += fmt.Sprintf("&%s=%s", "sqrlkey", sqrlkey)

	//  5. Add sqrlold

	// Sign the response URL
	sig := key.Sign([]byte(url))

	// Build the response body
	body := bytes.NewBufferString("sqrlsig=")
	body.Write(sig[:])

	request, err = http.NewRequest("POST", url, body)
	return
}

type Identity struct {
	Key
	Check [checkLen]byte
	Salt [saltLen]byte
	N, R, P int
}

// func NewIdentity(password string) *Identity {
// 	id := new(Identity)
// 	id.N, id.R, id.P = 16384, 8, 1
// 
// 	// Generate new 256-bit master key
// 	// key := cryptoRand(32)
// 
// 	// Generate new 64-bit salt
// 	// salt := cryptoRand(8)
// 	
// 	// Generate new 128-bit password check
// 
// 	// Generate new 256-bit key
// 
// 	return id
// }

func (this *Identity) recoverMasterKey(password string) (key *Key, err error) {
	// Derive userkey using password and this.Salt.
	userkey, keyhash, err := DeriveKey([]byte(password), this.Salt[:], this.N, this.R, this.P, keyLen)

	if err != nil {
		return
	}

	// Verify userkey by comparing keyhash to this.Check.
	n := len(this.Check)

	if subtle.ConstantTimeCompare(keyhash[:n], this.Check[:]) != 1 {
		err = errors.New("--")
		return
	}

	subtle.ConstantTimeCopy(1, key[:], userkey)
	Xor(key[:], this.Key[:])
	return
}

// ChangePassword
func (this *Identity) ChangePassword(old, new string) (ok bool, err error) {
	// Recover master key.
	master, err := this.recoverMasterKey(old)

	if err != nil {
		return
	}

	// Generate salt.
	salt := make([]byte, 8)
	rand.Read(salt)

	// Derive new userkey
	userkey, keyhash, err := DeriveKey([]byte(new), salt, this.N, this.R, this.P, keyLen)

	if err != nil {
		return
	}

	// Generate key by XORing master and userkey.
	key := make([]byte, keyLen)
	subtle.ConstantTimeCopy(1, key[:], userkey)
	Xor(key, master[:])

	// Change the stored values.
 	subtle.ConstantTimeCopy(1, this.Key[:keyLen], key[:keyLen])
 	subtle.ConstantTimeCopy(1, this.Check[:16], keyhash[:16])
 	subtle.ConstantTimeCopy(1, this.Salt[:8], salt[:8])
	return
}

func (this *Identity) GenerateKey(domain, password string) (key *PrivateKey, err error) {
	// Recover master key.
	master, err := this.recoverMasterKey(password)

	if err != nil {
		return
	}

	// HMAC-SHA256 using master as the key and domain as the message to generate the 256-bit private key.
 	mac := hmac.New(sha256.New, master[:])
	mac.Write([]byte(domain))
	bytes := mac.Sum(nil)

	if len(bytes) != keyLen {
		err = errors.New("--")
		return
	}

 	subtle.ConstantTimeCopy(1, key.Key[:keyLen], bytes[:keyLen])

	// Generate the corresponding 256-bit public key.
	key.generatePublicKey()
	return
}

// PrivateKey represents an Ed25519 private key.
type PrivateKey struct {
	Key
	PublicKey
}

// Sign hash msg and returns the signed hash
func (this *PrivateKey) Sign(msg []byte) (sig [64]byte) {
	var key *[ed25519.PrivateKeySize]byte
	subtle.ConstantTimeCopy(1, key[:32], this.Key[:])
	return *ed25519.Sign(key, msg)
}

func (this *PrivateKey) generatePublicKey() {
	var key *[ed25519.PrivateKeySize]byte
	subtle.ConstantTimeCopy(1, key[:32], this.Key[:])
	this.PublicKey = PublicKey(*ed25519.GeneratePublicKey(key))
}

// PublicKey represents an Ed25519 public key.
type PublicKey Key

// Verify verifies the signature in sig
func (this *PublicKey) Verify(msg []byte, sig [64]byte) bool {
	var key *[ed25519.PublicKeySize]byte
	subtle.ConstantTimeCopy(1, key[:32], this[:])
	return ed25519.Verify(key, msg, &sig)
}

//////////////////////// HELPER FUNCTIONS ////////////////////////

// cryptoRand returns n random bytes using crypto/rand.
func cryptoRand(n uint) (bytes []byte) {
	bytes = make([]byte, n)
	rand.Read(bytes)
	return
}

// hashKey returns the SHA256 hash of key.
func hashKey(key []byte) []byte {
	h := sha256.New()
	h.Write(key)
	return h.Sum(nil)
}

// verifyHash returns true if the first len(check) bytes of hash match check.
func verifyHash(hash, check []byte) (ok bool) {
	n := len(check)

	// Perform a constant time comparison. Return false if different.
	if subtle.ConstantTimeCompare(hash[:n], check) != 1 {
		return
	}

	// Everything is ok, return true.
	return true
}

// verifyKey compares the SHA256 hash of key against check.
func verifyKey(key, check []byte) (ok bool) {
	// Get the SHA256 hash of key.
	hash := hashKey(key)

	// Verify hash against check. Return false on failure.
	if verifyHash(hash, check) {
		return
	}

	// Everything is ok, return true.
	return true
}

// Xor sets a equal to a XOR b.
func Xor(a, b []byte) {
	for i := 0; i < len(a); i++ {
		a[i] ^= b[i]
	}
}

func DeriveKey(password, salt []byte, N, r, p, n int) (key, hash []byte, err error) {
	// Derive key using password and salt.
	key, err = scrypt.Key(password, salt, N, r, p, n)

	if err != nil {
		return
	}

	// Calculate the SHA256 hash of userkey.
	sha := sha256.New()
	sha.Write(key)
	hash = sha.Sum(nil)

	return
}