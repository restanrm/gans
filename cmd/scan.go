package cmd

import (
	"bufio"
	"encoding/gob"
	"github.com/codegangsta/cli"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
)

var CmdScan = cli.Command{
	Name:        "scan",
	Usage:       "Send IP addresses to main process",
	Action:      runScanner,
	Description: "This command receive IP adresses, network range or a file with an IP address per line and send it to manager.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "f, file",
			Value: "",
			Usage: "Send each line of the file to manager for scanning",
		},
	},
}

// This function extract list of IP Address from nmap command output in []byte
func filter_nmap_list_command(b []byte) []string {
	inlist := make([]string, 0, 10)
	outlist := make([]string, 0, 10)
	index := 0
	inlist = append(inlist, "")
	reg, err := regexp.Compile("Nmap scan report for ([a-zA-Z0-9.]+)")
	if err != nil {
		return nil
	}
	for _, char := range b { // Convert []byte into a []string
		if char != '\n' {
			inlist[index] = inlist[index] + string(char)
		} else {
			index += 1
			inlist = append(inlist, "")
		}
	}
	inlist = inlist[2 : len(inlist)-2]
	for _, line := range inlist {
		res := reg.FindStringSubmatch(line)
		if res != nil {
			outlist = append(outlist, res[1])
		}
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
				log.Fatal("Execution of \"nmap\" command failed: ", err)
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
