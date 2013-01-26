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
	//"strings"
)

// Configure the flags
var nworkers = flag.Int("n", 4096, "The number of concurrent connections.")
var serverinfo = "ssl.iskansloos.nl"
var total, wqid int

type WorkTodo struct {
	Host   string
	Bucket int
}

type WorkMessage struct {
	Id	 int
	C, D int
}

func fill_workqueue(queue chan WorkTodo) (int, int) {
	target := fmt.Sprintf("http://%s/get/", serverinfo)
	resp, err := http.Get(target)
	defer resp.Body.Close()
	if err != nil {
		fmt.Println(fmt.Sprintf("Error fetching worklist: %s", err))
		return 0, 0
	}

	// Decode json
	var m WorkMessage
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(fmt.Sprintf("Error reading worklist: %s", err))
		return 0, 0
	}
	err = json.Unmarshal(body, &m)

	// List all IP's in block
	total := 0
	for a := 0; a < 256; a++ {
		if a == 10 {
			continue // RFC 1918
		}
		for b := 0; b <= 255; b++ {
			if (a == 172) && (b > 15) && (b < 32) {
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
	resp, err := http.PostForm(target, formdata)
	defer resp.Body.Close()
	if err != nil {
		fmt.Println(fmt.Sprintf("ERROR posting cert: %s", err))
	}

}

// Report block as finished and break
func update_block_done(id int) {
	target := fmt.Sprintf("http://%s/done/%d/", serverinfo, id)
	resp, err := http.Get(target)
	defer resp.Body.Close()
	if err != nil {
	    fmt.Println("Error setting worklist as done ", err)
	}
}

// Worker function
func getcert(in chan WorkTodo) {
	config := tls.Config{InsecureSkipVerify: true}

	// Keep waiting for work
	for {
		target := <-in

		tcpconn, err := net.DialTimeout("tcp", target.Host, 2*time.Second)
		if err != nil {
			continue
		}
		conn := tls.Client(tcpconn, &config)
		err = conn.Handshake()
		if err != nil {
			continue
		}
		err = conn.Handshake()
		if err != nil {
			continue
		}
		state := conn.ConnectionState()
		for _, cert := range state.PeerCertificates {
			handle_cert(cert, target.Host)
		}
	}
}

func main() {
	// Make the worker chanels
	in := make(chan WorkTodo, 256*256)

	//	Start the workers
	for i := 0; i < *nworkers; i++ {
		go getcert(in)
	}

	// get work
	total, wqid = fill_workqueue(in)
	fmt.Println("Bucketid", wqid, "contains", total, "ip's")

	// Main loop getting and handling work
	for {
		percent := float64(len(in))/float64(cap(in))*100.00
		fmt.Println(fmt.Sprintf("%d", wqid), "done:", fmt.Sprintf("%f%%", percent), len(in), "/", cap(in))

		if len(in) == 0 {
			update_block_done(wqid)

			// Leave some time for the lingering connections to finish
			time.Sleep(5 * time.Second)

			// Get new work
			total, wqid = fill_workqueue(in)
			fmt.Println("Bucketid", wqid, "contains", total, "ip's")
		}

		time.Sleep(1 * time.Second)
	}
}