package sqrl

import (
	"github.com/kalaspuffar/base64url"
	"time"
	"math/rand"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
)

type Nonce struct {
	global_counter uint32
	aesKeyBlock cipher.Block	
}

func NewNonce() *Nonce {
	nonce := new(Nonce)
	nonce.global_counter = 0
	/*
		Create AES key for nut encryption
	*/
	rand.Seed(time.Now().Unix())
	aesKey := make([]byte, 16)
	binary.LittleEndian.PutUint32(aesKey[0:4], rand.Uint32())
	binary.LittleEndian.PutUint32(aesKey[4:8], rand.Uint32())
	binary.LittleEndian.PutUint32(aesKey[8:12], rand.Uint32())
	binary.LittleEndian.PutUint32(aesKey[12:16], rand.Uint32())
	aesKeyBlockRet, err := aes.NewCipher(aesKey)
	nonce.aesKeyBlock = aesKeyBlockRet
	if(err != nil) {
		fmt.Println(err)	
	}

	return nonce
}

/*
	Generate a 32 bytes (128 bits) nonce from ipv4 address, timestamp, counter and random as
	suggested in SQRL documentation (https://www.grc.com/sqrl/server.htm)
	Encode this with AES key generated at server start and return 
*/
func (r *Nonce) Generate(remoteAddr string) string {
	/*
		Prepare nut (128 bits)
	*/
	nut := make([]byte, 16)


	/*
		Prepare ipv4 address (32 bits)
	*/
	ipAddr := []byte(net.ParseIP(remoteAddr))
	ipv4Addr := ipAddr[len(ipAddr)-4:]
	copy(nut[0:4], ipv4Addr);

	/*
		Prepare unix timestamp (32 bits)
	*/
	binary.LittleEndian.PutUint32(nut[4:8], uint32(time.Now().Unix()))

	/*
		Prepare a global counter (32 bits)
	*/
	r.global_counter++
	binary.LittleEndian.PutUint32(nut[8:12], r.global_counter)

	/*
		Prepare a random uint32 (32 bits)
	*/	
	rand.Seed(time.Now().Unix())
	binary.LittleEndian.PutUint32(nut[12:16], rand.Uint32())
	
	/*
		Encrypt nut with AES key and return base64url encoded string.
	 */
	encryptedNut := make([]byte, 16)
	r.aesKeyBlock.Encrypt(encryptedNut, nut)
	return base64url.Encode(encryptedNut)
}