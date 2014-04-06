package sqrl

import (
	"code.google.com/p/rsc/qr"
	"github.com/kalaspuffar/base64url"
	"github.com/dustyburwell/ed25519"
	"crypto/subtle"
//	"time"
//	"net"
	"fmt"
	"io"
	"net/http"
)

type Server struct {
	nonce *Nonce
}

func NewServer() *Server {
	server := new(Server)
	server.nonce = NewNonce()
	return server
}

func (s *Server) AuthHandler() http.Handler {
	handler := func(w http.ResponseWriter, r *http.Request) {
		/*
			Parse form data and handle error messages. Might not be the most visible to the end user.
		*/
		err := r.ParseForm()
		if(err != nil) {
			fmt.Println(err)
			return
		}

		message := r.FormValue("message")
		signature := r.FormValue("signature")
		publicKey := r.FormValue("publicKey")

		/*
			Decode publicKey and signature to a byte array using base64url package
		*/
		pubBytes, pubErr := base64url.Decode(publicKey)
		if pubErr != nil {
			fmt.Println(pubErr)
		}
		signBytes, signErr := base64url.Decode(signature)
		if signErr != nil {
			fmt.Println(signErr)
		}

		/*
			Change the byte array to an object with the correct sizes used by the ed25519 implementation
		*/
		var pk *[ed25519.PublicKeySize]byte
		pk = new([ed25519.PublicKeySize]byte)
		subtle.ConstantTimeCopy(1, pk[:32], pubBytes)
		var sig *[ed25519.SignatureSize]byte
		sig = new([ed25519.SignatureSize]byte)
		subtle.ConstantTimeCopy(1, sig[:64], signBytes)

		/*
			Verify the signature and return verified or not depending on the result.
		*/
		w.Header().Add("Content-Type", "text/html")
		if ed25519.Verify(pk, []byte(message), sig) {
			io.WriteString(w, "{result:true}Verified")
		} else {
			io.WriteString(w, "{result:false}Not Verified")
		}
	}
	return http.HandlerFunc(handler)
}

func (s *Server) QRHandler(path string) http.Handler {
	handler := func(w http.ResponseWriter, r *http.Request) {
		url := ""		

		if r.TLS == nil {
			url += "qrl://"
		} else {
			url += "sqrl://"
		}

		url += r.Host
		url += "/" + path + "?"
		url += r.URL.RawQuery
		url += "&nut="
		url += s.nonce.Generate(r.RemoteAddr)

		// w.Header().Add("Content-Type", "text/html")
		// io.WriteString(w, fmt.Sprintf("%#v<br/><br/>", url))
		// io.WriteString(w, fmt.Sprintf("%#v<br/><br/>", *r.URL))
		// io.WriteString(w, fmt.Sprintf("%#v<br/><br/>", *r))

		w.Header().Add("Content-Type", "image/png")
		qrcode, err := qr.Encode(url, qr.M)

		if err != nil {
			return
		}

		w.Write(qrcode.PNG())
	}

	return http.HandlerFunc(handler)
}