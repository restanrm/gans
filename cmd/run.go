package cmd

import (
	"encoding/gob"
	"fmt"
	"github.com/codegangsta/cli"
	"io"
	"log"
	"net"
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
	},
}

var database_file string
var scans Scans

func workerPool(workerPoolSize int, input_work chan *Scan) {
	for i := 0; i < workerPoolSize; i++ {
		go worker(<-input_work)
	}
}

func worker(inputScan *Scan) {
	inputScan.Status = icmp_in_progress
	// do the ping
	// put result in inputScan.Result.Icmp
	inputScan.Status = nmap_in_progress
	// do the scanning function
	// store result in Scan.Result.Nmap
	inputScan.Status = finished
}

func listenGansScan(listen_address string) {
	log.Print("Waiting for incomming connection")
	ln, err := net.Listen("tcp", listen_address)
	if err != nil {
		log.Fatal("Could not start listen for incomming data to scan: ", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Print("Could not open connexion for this client : ", err)
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
		for _, s := range scans {
			if scan.Equal(&s) {
				fmt.Printf("%v already in database\n", scan.Host)
				ok = true
			}
		}
		if !ok {
			scans = append(scans, scan)
		} else {
			continue
		}
		fmt.Printf("received order to scan IP: %v\n", scan.Host)
		// verify if data is not already into worker and send it to worker if it is not the case.
	}
}

func runScan(c *cli.Context) {
	fmt.Println("Commande principale qui permet de faire fonctionner les scan en tâche de fond")
	scans = make(Scans, 0, 100)
	// read work data from datafile where everything is stored.
	log.Print("Read data from saved files")
	database_file = c.String("database")
	scans.Load(database_file)

	// launch workers
	var work_input chan *Scan = make(chan *Scan, 10)
	workerPool(5, work_input)
	log.Print("Launching worker to nmap scan dest files")
	//comm := WorkerPool(5)
	// Create workers
	//
	// boucle infini sur la recherche de machines à scanner dans la base de données
	//
	// envoi de ces données de scan aux workers

	//input := WorkerPool(5)

	// check for work in current data
	log.Print("checking for work in data readed from configuration files")
	log.Print("Sending data to worker")

	// écoute des connexions réseau :

	listenGansScan(c.String("listen"))

}
