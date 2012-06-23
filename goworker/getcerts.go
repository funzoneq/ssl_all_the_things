package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Configure the flags
var nworkers = flag.Int("n", 256, "The number of concurrent connections.")
var serverinfo = "ssl.iskansloos.nl"

type WorkTodo struct {
	Host   string
	Bucket int
}

type WorkMessage struct {
	Id   int
	C, D int
}

func fill_workqueue(queue chan WorkTodo, host string) (int, int) {
	target := fmt.Sprintf("http://%s/get/", host)
	resp, err := http.Get(target)
	if err != nil {
        fmt.Println("Error fetching worklist")
		return 0, 0
	}
	// Decode json
	var m WorkMessage
	body, err := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &m)

    resp.Body.Close()

	// List all IP's in block
	total := 0
	for a := 0; a < 256; a++ {
		if a == 10 {
			continue // RFC 1918
		}
		for b := 0; b <= 255; b++ {
			if (a == 127) && (b > 15) && (b < 32) {
				continue // RFC 1918
			}
			if (a == 192) && (b == 168) {
				continue // RFC 1918
			}
			total++
			queue <- WorkTodo{fmt.Sprintf("%d.%d.%d.%d:443", a, b, m.C, m.D), m.Id}
		}
	}
	return total, m.Id
}

func handle_cert(cert *x509.Certificate, host string) {
    block := pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
    pemdata := string(pem.EncodeToMemory(&block))
    formdata := url.Values{}
    formdata.Set("commonname", cert.Subject.CommonName)
    formdata.Set("pem", pemdata)
    formdata.Set("endpoint", host)
	target := fmt.Sprintf("http://%s/post/", serverinfo)
    _, err := http.PostForm(target, formdata)
    if err != nil {
        fmt.Println("ERROR posting cert")
    }
}

func handle_hostname(hostname string) {
	formdata := url.Values{}
	formdata.Set("hostname", hostname)
	target := fmt.Sprintf("http://%s/hostname/", serverinfo)
	_, err := http.PostForm(target, formdata)
    if err != nil {
        fmt.Println("ERROR posting hostname")
    }
}

// Worker function
func getcert(in chan WorkTodo, out chan int) {
	config := tls.Config{InsecureSkipVerify: true}
	// Keep waiting for work
	for {
		target := <-in
		hostname, err := net.LookupAddr(target.Host)
		if err == nil {
			handle_hostname(hostname[0])
		}

        tcpconn, err := net.DialTimeout("tcp", target.Host, 2*time.Second)
		if err != nil {
            out <- 1
			continue
		}
		conn := tls.Client(tcpconn, &config)
		err = conn.Handshake()
		if err != nil {
            out <- 1
			continue
		}
		err = conn.Handshake()
		if err != nil {
            out <- 1
			continue
		}
		state := conn.ConnectionState()
		// TODO: store certificate
		for _, cert := range state.PeerCertificates {
			handle_cert(cert, target.Host)
		}
		conn.Close()
        out <- 1
	}
}

func main() {
	host := serverinfo

	// Make the worker chanels
	in := make(chan WorkTodo, 256*256)
	out := make(chan int, 256*256)

	//  Start the workers
    for i := 0; i < *nworkers; i++ {
		go getcert(in, out)
	}

	// Main loop getting and handling work
	for {
		total, id := fill_workqueue(in, host)
		if total == 0 {
			fmt.Println("Failed to fetch work queue, retry")
			//break
		} else {
			fmt.Println("Bucketid", id, "contains", total, "ip's")

			// get results
			for {
				<-out
				total--
				if total == 0 {
					// Report block as finished and break
					target := fmt.Sprintf("%s/done/%d/", host, id)
	                _, err := http.Get(target)
	                if err != nil {
	                    fmt.Println("Error setting worklist as done")
	                }

					//break // Break and get a new block
				}
			}
		}
	}

}
