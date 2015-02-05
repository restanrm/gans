package cmd

import (
	"github.com/codegangsta/cli"
	"strings"
	//	"database/sql"
//	_ "github.com/mattn/go-sqlite3"
	"log"
	"os/exec"
	"encoding/gob"
	"net"
//	"encoding/json"
	"fmt"
//	"github.com/restanrm/scanner/dao"
)

var CmdScan = cli.Command{
	Name:   "scan",
	Usage:  "Ajoute des IP dans la base de données",
	Action: runScanner,
	Description: "Cette commande reçoit des adresses ou plages d'adresses au format de nmap pour les ajouter dans la base de données des adresses à scanner.", 
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "f, file",
			Usage: "With this argument, the first argument is considered as a file with an IP at each line",
		},
	},
}

/* Cette commande permet d'extraire une liste d'adresse IP à partir un tableau d'octets */
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

func runScanner(c *cli.Context) {
	// init bdd
	if !c.Args().Present() {
		log.Fatal("Pas d'argument, voir les consignes d'utilisations.")
	}
	/*
	con, err := dao.Open("./database.sqlite3")
	if err != nil {
		log.Fatal(err)
	}
	defer con.Close()
	*/

	// Connexion au serveur de gestion des scan
	conn, err := net.Dial("tcp", "localhost:3999")
	if err != nil {
		log.Fatal("Failed to connect to server: ", err) 
	}
	defer conn.Close()
	encoder := gob.NewEncoder(conn)

	log.Print("Lancement de Nmap pour obtenir la liste des adresses correspondant à : ", c.Args().First())
	nmap_list_bytes, err := exec.Command("nmap", "-n", "-sL", c.Args().First()).Output()
	if err != nil {
		log.Fatal(err)
	}
	outlist := filter_nmap_list_command(nmap_list_bytes)

	for _, elt := range outlist {
		scan := Scan{elt, null, Result{}}
		fmt.Println(scan)
		encoder.Encode(scan)
	}
	log.Print("Data sent to server")
}
