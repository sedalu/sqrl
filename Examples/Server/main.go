package main

import (
	"fmt"
	"github.com/sedalu/sqrl"
	"io"
	"net/http"
)

// hello world, the web server
func HelloServer(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	io.WriteString(w, "hello, world!\n")
	io.WriteString(w, "<a href=\"/qr.png?xyz\">QR Code</a>\n")
}

func main() {
	http.HandleFunc("/sqrl", HelloServer)

	http.Handle("/qr.png", sqrl.QRHandler("sqrl"))

	err := http.ListenAndServe(":8080", nil)

	if err != nil {
		fmt.Println(err)
	}
}