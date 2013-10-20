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

type Client struct {
	
}

// Authenticate
func (this *Client) Authenticate(id *Identity, password, siteUrl string, options Option) (request *http.Request, err error) {
	// Get the domain.
	domain := "example.com"

	// Get the private key for the domain.
	masterKey, err := id.recoverMasterKey(password)
	key := masterKey.DomainKey(domain)

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
	sqrlkey := base64.URLEncoding.EncodeToString(key.PublicKey()[:])
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
	*Key
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
	key, err = DeriveKey([]byte(password), this.Salt[:], this.N, this.R, this.P, keyLen)

	if err != nil {
		return
	}

	if !this.Authenticate(key) {
		err = errors.New("--")
		return
	}

	key.Xor(this.Key)
	return
}

func (this *Identity) Authenticate(key *Key) bool {
	hash := key.Hash()

	if subtle.ConstantTimeCompare(hash[:checkLen], this.Check[:]) != 1 {
		return false
	}

	return true
}

// ChangePassword
func (this *Identity) ChangePassword(old, new string) (ok bool, err error) {
	// Recover master key.
	master, err := this.recoverMasterKey(old)

	if err != nil {
		return
	}

	salt := cryptoRand(saltLen)
	key, err := DeriveKey([]byte(new), salt, this.N, this.R, this.P, keyLen)

	if err != nil {
		return
	}

	key.Xor(master)
 	subtle.ConstantTimeCopy(1, this.Key[:keyLen], key[:keyLen])
 	subtle.ConstantTimeCopy(1, this.Check[:16], key.Hash()[:16])
 	subtle.ConstantTimeCopy(1, this.Salt[:8], salt[:8])
	return
}

// Signature represents a 512-bit cryptographic signature.
type Signature [64]byte

// Key represents a 256-bit cryptographic key.
type Key [keyLen]byte

// DomainKey returns the private key for domain.
// HMAC-SHA256 using k as the key and domain as the message to generate the 256-bit private key.
func (k *Key) DomainKey(domain string) (key *Key) {
 	mac := hmac.New(sha256.New, k[:])
	mac.Write([]byte(domain))
	bytes := mac.Sum(nil)
 	subtle.ConstantTimeCopy(1, key[:keyLen], bytes[:keyLen])
	return
}

// Hash returns the SHA256 hash
func (k *Key) Hash() []byte {
	hash := sha256.New()
	hash.Write(k[:])
	return hash.Sum(nil)
}

// PublicKey returns the corresponding public key.
func (k *Key) PublicKey() *Key {
	var pk *[ed25519.PrivateKeySize]byte
	subtle.ConstantTimeCopy(1, pk[:32], k[:])
	key := Key(*ed25519.GeneratePublicKey(pk))
	return &key
}

// Sign returns the cryptographic signature of the []byte msg.
func (k *Key) Sign(msg []byte) (sig *Signature) {
	var pk *[ed25519.PrivateKeySize]byte
	subtle.ConstantTimeCopy(1, pk[:32], k[:])
	s := Signature(*ed25519.Sign(pk, msg))
	return &s
}

// Verify returns true if the cryptographic signature sig.
func (k *Key) Verify(msg []byte, sig *Signature) bool {
	var pk *[ed25519.PublicKeySize]byte
	subtle.ConstantTimeCopy(1, pk[:32], k[:])
	// pk := [ed25519.PublicKeySize]byte(*k)
	s := [ed25519.SignatureSize]byte(*sig)
	return ed25519.Verify(pk, msg, &s)
}

func (k *Key) Xor(key *Key) {
	for i := 0; i < keyLen; i++ {
		k[i] ^= key[i]
	}
}

//////////////////////// HELPER FUNCTIONS ////////////////////////

// cryptoRand returns n random bytes using crypto/rand.
func cryptoRand(n int) (bytes []byte) {
	bytes = make([]byte, n)
	rand.Read(bytes)
	return
}

// Xor sets a equal to a XOR b.
func Xor(a, b []byte) {
	for i := 0; i < len(a); i++ {
		a[i] ^= b[i]
	}
}

func DeriveKey(password, salt []byte, N, r, p, n int) (key *Key, err error) {
	// Derive key using password and salt.
	k, err := scrypt.Key(password, salt, N, r, p, n)

	if err != nil {
		return
	}

	subtle.ConstantTimeCopy(1, key[:], k)
	return
}