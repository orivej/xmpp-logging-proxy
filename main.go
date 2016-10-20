package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/orivej/e"
	"github.com/pkg/errors"
)

type ReadResult struct {
	n   int
	err error
	buf []byte
}

type Log func(side, data string)

const (
	bufSize               = 4000
	clientTLSMarker       = "<starttls"
	serverTLSMarker       = "<proceed"
	clientAuthMarker      = "<auth"
	clientAuthReplacement = "<auth>CENSORED</auth>"
)

var (
	flListenAddress = flag.String("listen", ":5222", "listen address")
	flServer        = flag.String("server", "<server:port>", "target server:port")
	flLogDir        = flag.String("log-dir", "", "directory for session logs")
	flCensor        = flag.Bool("censor", false, "censor credentials from the log")

	flKeyPath  = flag.String("key", "", "path to TLS certificate key")
	flCertPath = flag.String("cert", "", "path to TLS certificate")

	flReplaceLocal  = flag.String("replace-local", "", "")
	flReplaceRemote = flag.String("replace-remote", "", "")
)

func main() {
	flag.Parse()

	certificate, err := tls.X509KeyPair([]byte(localhostCert), []byte(localhostKey))
	e.Exit(err)
	if len(*flCertPath) > 0 {
		certificate, err = tls.LoadX509KeyPair(*flCertPath, *flKeyPath)
		e.Exit(errors.Wrap(err, "can not load TLS key pair"))
	}

	listener, err := net.Listen("tcp", *flListenAddress)
	e.Exit(err)

	for idx := nextIdx(); true; idx++ {
		idx := idx
		client, err := listener.Accept()
		e.Exit(err)

		var f *os.File
		if *flLogDir != "" {
			path := filepath.Join(*flLogDir, logName(idx))
			flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
			f, err = os.OpenFile(path, flags, 0666)
			e.Exit(err)
		}
		pr := func(side, data string) {
			ts := time.Now().Format(time.RFC3339)
			fmt.Printf("%04d %s %s %s\n", idx, ts, side, data)
			if f != nil {
				fmt.Fprintf(f, "%s %s %s\n", ts, side, data)
			}
		}

		go func() {
			defer e.CloseOrPrint(client)
			defer e.CloseOrPrint(f)
			err := serve(client, pr, certificate)
			pr("X", err.Error())
		}()
	}
}

func nextIdx() int {
	if *flLogDir == "" {
		return 1
	}

	files, err := ioutil.ReadDir(*flLogDir)
	e.Exit(err)

	idx := 1
	var n int
	for _, file := range files {
		_, err := fmt.Sscanf(file.Name(), "%d.log", &n)
		if err == nil && idx <= n {
			idx = n + 1
		}
	}
	return idx
}

func logName(idx int) string {
	return fmt.Sprintf("%04d.log", idx)
}

func serve(client net.Conn, pr Log, certificate tls.Certificate) error {
	server, err := net.Dial("tcp", *flServer)
	if err != nil {
		return errors.Wrap(err, "failed to connect to server")
	}
	defer e.CloseOrPrint(server)

	err = proxy(client, server, pr, true)
	if err != nil {
		return errors.Wrap(err, "session terminated")
	}

	tlsClient := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{certificate},
	})
	tlsServer := tls.Client(server, &tls.Config{
		InsecureSkipVerify: true,
	})
	// pr("X", "establishing TLS")
	err = proxy(tlsClient, tlsServer, pr, false)
	return errors.Wrap(err, "TLS session terminated")
}

func proxy(client, server io.ReadWriter, pr Log, untilTLS bool) error {
	clientNext, clientResults := startReader(client)
	serverNext, serverResults := startReader(server)

	censor := *flCensor
	rLocal := []byte(*flReplaceLocal)
	rRemote := []byte(*flReplaceRemote)
	replace := len(rLocal) > 0 && len(rRemote) > 0

	for {
		select {
		case result := <-clientResults:
			err := result.err
			if err != nil {
				return errors.Wrap(err, "failed to read from client")
			}

			buf := result.buf[:result.n]
			if replace {
				buf = bytes.Replace(buf, rLocal, rRemote, -1)
			}
			if censor && bytes.Contains(buf, []byte(clientAuthMarker)) {
				censor = false
				pr("?", clientAuthReplacement)
			} else {
				pr("?", escape(string(buf)))
			}

			_, err = server.Write(buf)
			if err != nil {
				return errors.Wrap(err, "failed to write to server")
			}

			if untilTLS && bytes.Contains(buf, []byte(clientTLSMarker)) {
				// pr("X", "client requests TLS")
				clientNext <- false
				continue
			}

			clientNext <- true

		case result := <-serverResults:
			err := result.err
			if err != nil {
				return errors.Wrap(err, "failed to read from server")
			}

			buf := result.buf[:result.n]
			pr("!", escape(string(buf)))
			if replace {
				buf = bytes.Replace(buf, rRemote, rLocal, -1)
			}

			_, err = client.Write(buf)
			if err != nil {
				return errors.Wrap(err, "failed to write to client")
			}

			if untilTLS && bytes.Contains(buf, []byte(serverTLSMarker)) {
				// pr("X", "server approves TLS")
				serverNext <- false
				return nil
			}

			serverNext <- true
		}
	}
}

func startReader(reader io.Reader) (chan<- bool, chan ReadResult) {
	readNext := make(chan bool)
	buf := make([]byte, bufSize)
	results := make(chan ReadResult)
	go func() {
		for {
			n, err := reader.Read(buf)
			results <- ReadResult{n, err, buf}
			if !<-readNext {
				return
			}
		}
	}()
	return readNext, results
}

var escaper = strings.NewReplacer(
	"\\", "\\\\",
	"\n", "\\n",
	"\r", "\\r",
)

func escape(s string) string {
	return escaper.Replace(s)
}
