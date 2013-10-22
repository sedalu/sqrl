package sqrl

import (
	"code.google.com/p/rsc/qr"
	// "fmt"
	// "io"
	"net/http"
)

func QRHandler(path string) http.Handler {
	handler := func(w http.ResponseWriter, r *http.Request) {
		url := ""

		if r.TLS == nil {
			url += "qrl://"
		}

		url += r.Host
		url += "/" + path + "?"
		url += r.URL.RawQuery

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