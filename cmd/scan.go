package cmd

import (
	"bufio"
	"encoding/gob"
	"github.com/codegangsta/cli"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	// "fmt"
)

var CmdScan = cli.Command{
	Name:        "scan",
	Usage:       "Envoi des adresses IP à scanner au processus principal",
	Action:      runScanner,
	Description: "Cette commande reçoit des adresse IP ou des plages d'adresses IP ou un fichiers de description, et les envois au manager.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "f, file",
			Value: "",
			Usage: "Send each line of the file to manager for scanning",
		},
	},
}

// This function extract list of IP Address from nmap command output in []byte
func filter_nmap_list_command(b []byte) []string {
	outlist := make([]string, 0, 10)
	index := 0
	outlist = append(outlist, "")
	for _, char := range b { // Convert []byte into a []string
		if char != '\n' {
			outlist[index] = outlist[index] + string(char)
		} else {
			index += 1
			outlist = append(outlist, "")
		}
	}
	outlist = outlist[2 : len(outlist)-2]
	for i, line := range outlist { // get only the 5th elements of the line
		outlist[i] = strings.Fields(line)[4]
	}
	return outlist
}

// Create a new connection to the server
func newConnection() net.Conn {
	conn, err := net.Dial("tcp", "localhost:3999")
	if err != nil {
		log.Fatal("Failed to connect to server: ", err)
	}
	return conn
}

func runScanner(c *cli.Context) {
	if !c.Args().Present() && (c.String("file") == "") {
		cli.ShowCommandHelp(c, "scan")
	}

	// Connexion au serveur de gestion des scan
	conn := newConnection()
	defer conn.Close()

	//initialisation de l'encodeur
	encoder := gob.NewEncoder(conn)

	if c.String("file") != "" {
		file, err := os.Open(c.String("file"))
		if err != nil {
			log.Fatal("Could not open file:  ", err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			elt := scanner.Text() // need to filter data from client.
			scan := Scan{elt, null, Result{}}
			encoder.Encode(scan)
		}
		log.Printf("IP addresses from %q has been sent\n", c.String("file"))
	} else {
		// for each argument, run nmap on it and send it to network
		for _, argument := range c.Args() {
			nmap_list_bytes, err := exec.Command("nmap", "-n", "-sL", argument).Output()
			if err != nil {
				log.Fatal("L'execution de la commande « nmap » n'as pas fonctionnée : ", err)
			}
			outlist := filter_nmap_list_command(nmap_list_bytes)
			if len(outlist) == 0 { // if outlist is void, pass
				continue
			}
			for _, elt := range outlist {
				scan := Scan{elt, null, Result{}}
				encoder.Encode(scan)
			}
			log.Printf("IP address from %v has been sent\n", argument)
		}
	}
}
