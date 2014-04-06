package main

import (
	"fmt"
//	"github.com/sedalu/sqrl"
	"github.com/kalaspuffar/sqrl"
	"io"
	"net/http"
)

// hello world, the web server
func HelloServer(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	io.WriteString(w, "hello, world!\n")
	io.WriteString(w, "<img src=\"/qr.png?testparam=test\" />\n") 
}

func main() {
	http.HandleFunc("/hello", HelloServer)
	server := sqrl.NewServer()
	http.Handle("/qr.png", server.QRHandler("sqrl"))
	http.Handle("/sqrl", server.AuthHandler())

	err := http.ListenAndServe(":8080", nil)

	if err != nil {
		fmt.Println(err)
	}
}