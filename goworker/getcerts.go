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
var nworkers = flag.Int("n", 256, "The number of concurrent connections.")
var sem = make(chan int, 65)
var serverinfo = "ssl.iskansloos.nl"
var total, wqid, errors int

type WorkTodo struct {
	Host   string
	Bucket int
}

type WorkMessage struct {
	Id	 int
	C, D int
}

type PTRrecord struct {
	Host 	string
	IP 		string
}

func fill_workqueue(queue chan WorkTodo, host string) (int, int) {
	target := fmt.Sprintf("http://%s/get/", host)
	resp, err := http.Get(target)
	if err != nil {
		fmt.Println(fmt.Sprintf("Error fetching worklist: %s", err))
		return 0, 0
	}
	defer resp.Body.Close()

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
	if err != nil {
		fmt.Println(fmt.Sprintf("ERROR posting cert: %s", err))
	}
	defer resp.Body.Close()
}

func handle_hostname(done chan PTRrecord) {
	//target := fmt.Sprintf("http://%s/hostname/", serverinfo)

	var v PTRrecord
	formdata := url.Values{}
	for c := 0; c < len(done); c++ {
		v = <- done
		formdata.Set(fmt.Sprintf("hostname[%d]", c), fmt.Sprintf("%s:%s", v.Host, v.IP))
	}
	//_, err := http.PostForm(target, formdata)
	//if err != nil {
	//	fmt.Println(fmt.Sprintf("ERROR posting hostname: %s", err))
	//}
}

// Report block as finished and break
func update_block_done(host string, id int) {
	target := fmt.Sprintf("http://%s/done/%d/", host, id)
	resp, err := http.Get(target)
	if err != nil {
	    fmt.Println("Error setting worklist as done ", err)
	}
	defer resp.Body.Close()
}

func lookup_PTRrecord (done chan PTRrecord, ip string) {
	hostname, err := net.LookupAddr(ip)
	if err == nil {
		done <- PTRrecord{hostname[0], ip}
	}
}

// Worker function
func getcert(in chan WorkTodo, done chan PTRrecord) {
	config := tls.Config{InsecureSkipVerify: true}
	// Keep waiting for work
	for {
		target := <-in
		//ip := strings.Split(target.Host, ":")
		//go lookup_PTRrecord(done, ip[0])

		tcpconn, err := net.DialTimeout("tcp", target.Host, 2*time.Second)
		if err != nil {
			continue
		}
		defer conn.Close()
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
		// TODO: store certificate
		for _, cert := range state.PeerCertificates {
			handle_cert(cert, target.Host)
		}
	}
}

func main() {
	// Make the worker chanels
	in := make(chan WorkTodo, 256*256)
	done := make(chan PTRrecord, 256*256)
	errors = 0

	//	Start the workers
	for i := 0; i < *nworkers; i++ {
		go getcert(in, done)
	}

	// Don't update on the first run
	update := false

	// Main loop getting and handling work
	for {
		if len(in) == 0 {
			total, wqid = fill_workqueue(in, serverinfo)
			fmt.Println("Bucketid", wqid, "contains", total, "ip's")

			if total == 0 && wqid == 0 {
				errors++
			}

			if update {
				update_block_done(serverinfo, wqid)
			}

			update = true
		}

		if len(done) > *nworkers {
			handle_hostname(done)
		}

		if errors > 5 {
			// weird state, exit the program
			break
		}

		percent := float64(len(in))/float64(cap(in))*100.00
		fmt.Println(fmt.Sprintf("%d", wqid), "done:", fmt.Sprintf("%f%%", percent), len(in), "/", cap(in), "backlog:", len(done))
		time.Sleep(1 * time.Second)
	}

}
