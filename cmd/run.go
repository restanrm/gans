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
}

/*
type Scan struct {
	Path, IPRange string
}

func WorkerPool(workerPoolSize int) chan Scan {
	var inputScan chan Scan = make(chan Scan)
	for i := 0; i < workerPoolSize; i++ {
		go worker(inputScan)
	}
	return inputScan
}

func worker(inputScan chan Scan) {
	// do the scanning function and store result in Scan.Path files

}
*/

func listenGansScan() {
	log.Print("Waiting for incomming connection")
	ln, err := net.Listen("tcp", "127.0.0.1:3999")
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
	for {
		var scan Scan
		err := dec.Decode(&scan)
		switch {
		case err == io.EOF:
			return
		case err != nil:
			log.Print("Could not decode packet from client : ", err)
		}
		fmt.Printf("received order to scan IP: %v\n", scan.Host)
		// verify if data is not already into worker and send it to worker if it is not the case.
	}
}

func runScan(c *cli.Context) {
	fmt.Println("Commande principale qui permet de faire fonctionner les scan en tâche de fond")

	// read work data from datafile where everything is stored.
	log.Print("Read data from saved files")

	// launch workers
	log.Print("Launching worker to nmap scan dest files")
	// getAllHostList(con)
	//
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

	listenGansScan()

}
