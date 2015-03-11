package cmd

import (
	"encoding/gob"
	"fmt"
	"github.com/codegangsta/cli"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

var CmdRun = cli.Command{
	Name:   "run",
	Usage:  "Lance les routines de scan des adresses de destinations",
	Action: runScan,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "listen, l",
			Value: "localhost:3999",
			Usage: "Set listen address and port",
		},
		cli.StringFlag{
			Name:  "database, d",
			Value: "test.json",
			Usage: "Database filename for Json output",
		},
		cli.IntFlag{
			Name:  "notification-delay, n",
			Value: 5,
			Usage: "This is the notification delay to keep track of current working scan",
		},
		cli.IntFlag{
			Name:  "worker, w",
			Value: 5,
			Usage: "Handle number of thread simultaneously running",
		},
	},
}

var (
	database_file      string
	scans              Scans
	ch_scan            chan *Scan
	mutex              sync.Mutex
	notification_delay time.Duration
)

const buffered_channel_size = 1 << 16

func workerPool(workerPoolSize int) {
	for i := 0; i < workerPoolSize; i++ {
		go worker()
	}
}

func worker() {
	var s *Scan
	var err error
	var cmd *exec.Cmd
	for {
		s = <-ch_scan
		log.Printf("Received Work : %v\n", s.Host)
		s.Status = icmp_in_progress
		// do the ping
		cmd = exec.Command("/bin/ping", "-c", "2", s.Host)
		s.Result.Icmp, err = cmd.Output()
		if err != nil {
			log.Printf("Failed to ping destination %s: %s", s.Host, err)
			s.Result.Icmp = []byte("Failed")
		}
		s.Status = nmap_in_progress
		log.Printf("Ping done for %v\n", s.Host)
		// Prepare « nmap » command and call
		cmd = exec.Command("nmap",
			"-n",
			"-T3",
			"-sS",
			"-sV",
			"-oX", "-",
			"--verbose",
			"-p -",
			s.Host)
		result := make(chan []byte)
		ticker := time.Tick(notification_delay)
		// There is a goroutine to handle long treatment
		// this is used to keep monitoring of « nmap » activity
		go func() {
			tmp, err := cmd.Output()
			if err != nil {
				log.Printf("Failed to nmap destination %s: %s", s.Host, err)
			}
			result <- tmp
		}()
		for end := false; !end; {
			select {
			case s.Result.Nmap = <-result:
				s.Status = finished
				log.Printf("Finished Work for %v\n", s.Host)
				mutex.Lock()
				scans.Save(database_file)
				mutex.Unlock()
				end = true
			case <-ticker:
				log.Printf("Work in progress for %v\n", s.Host)
			}
		}
	}
}

func listenGansScan(listen_address string) {
	log.Print("Waiting for incoming connection")
	ln, err := net.Listen("tcp", listen_address)
	if err != nil {
		log.Fatal("Could not start listen for incoming data to scan: ", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Print("Could not open connection for this client : ", err)
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	dec := gob.NewDecoder(conn)
	// Save all captured order to file "test.json" for now when the client is closing connection
	defer func() {
		err := scans.Save(database_file)
		if err != nil {
			log.Print("Could not save data to file : ", err)
		}
	}()
	for {
		var scan Scan
		err := dec.Decode(&scan)
		switch {
		case err == io.EOF:
			return
		case err != nil:
			log.Print("Could not decode packet from client : ", err)
		}
		var ok bool
		// this allow to verify if scan is not already in the scan list
		for _, s := range scans {
			if scan.Host == s.Host {
				fmt.Printf("%v already in database\n", scan.Host)
				ok = true
			}
		}
		if !ok {
			scans = append(scans, scan)
			ch_scan <- &scans[len(scans)-1]
		} else {
			continue
		}
	}
}

func runScan(c *cli.Context) {
	// Check for root now, better solution has to be found
	if os.Geteuid() != 0 {
		fmt.Println("This program need to have root permission to execute nmap for now.")
		os.Exit(1)
	}

	notification_delay = time.Duration(c.Int("notification-delay")) * time.Second

	// création de la structure de scan
	scans = make(Scans, 0, 100)

	// read work data from datafile where everything is stored.
	log.Print("Read data from saved files")
	database_file = c.String("database")
	scans.Load(database_file)

	// launch workers
	log.Print("Launching worker to nmap scan dest files")
	ch_scan = make(chan *Scan, buffered_channel_size)
	workerPool(c.Int("worker"))

	// initial feeder
	for i := 0; i < len(scans); i++ {
		if scans[i].Status != finished {
			ch_scan <- &scans[i]
		}
	}

	// écoute des connexions réseau :
	listenGansScan(c.String("listen"))

}
