package cmd

import (
	"database/sql"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/codegangsta/cli"
	_ "github.com/go-sql-driver/mysql"
	"github.com/restanrm/gans/nmap"
	"log"
	//	"os"
	"strings"
)

var CmdParse = cli.Command{
	Name:      "parse",
	Usage:     "Parse les données des fichiers nmap en entré et les places dans la base de données",
	ShortName: "xml",
	Action:    parseRun,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "user, u",
			Usage: "utilisateur de la base de données",
			Value: "root",
		},
		cli.StringFlag{
			Name:  "password, p",
			Usage: "Mot de passe de connection à la base de données",
			Value: "amossys35;",
		},
		cli.StringFlag{
			Name:  "database, d",
			Usage: "Nom de la base de données de saisie des hôtes",
			Value: "gans",
		},
		cli.BoolFlag{
			Name:  "ClearText, c",
			Usage: "Désactive la sauvegarde en base de données et préfère une sortie texte des donnée",
		},
	},
}

func getNmapHostId(con *sql.DB, hosts []nmap.XMLHost) (int, error) {
	hostid := make([]int, 0, 3)
	for _, host := range hosts {
		for _, address := range host.Address {
			var t int
			err := con.QueryRow("select id from host where ipv4=?", string(address.Addr)).Scan(&t)
			if err != nil {
				return -1, err
			}
			hostid = append(hostid, t)
		}
	}

	switch len(hostid) {
	case 1:
		return hostid[0], nil
	case 2:
		log.Print("Multiple hostid, returning only the first")
		return hostid[0], nil
	default:
		return -1, errors.New("Could not get hostid")
	}
}

func queryServiceId(con *sql.DB, hostid int, port nmap.XMLPort) {
	var t int
	var err error
	if port.Service != nil {
		err = con.QueryRow("select id from service where hostid=? and port=? and protocol=? and product=? and version=? and service=?",
			hostid, port.Portid, port.Protocol, port.Service.Product, port.Service.Version, port.Service.Name).Scan(&t)
	} else {
		err = con.QueryRow("select id from service where hostid=? and port=? and protocol=?", hostid, port.Portid, port.Protocol).Scan(&t)
	}
	switch {
	case err == sql.ErrNoRows:
		var err error
		if port.Service != nil && port.State != nil {
			_, err = con.Exec("INSERT INTO service (hostid, port, protocol, service, state, product, version) VALUES (?,?,?,?,?,?,?)",
				hostid, port.Portid, port.Protocol, port.Service.Name, port.State.State, port.Service.Product, port.Service.Version)
		} else if port.Service != nil && port.State == nil {
			_, err = con.Exec("INSERT INTO service (hostid, port, protocol, service, product, version) VALUES (?,?,?,?,?,?)",
				hostid, port.Portid, port.Protocol, port.Service.Name, port.Service.Product, port.Service.Version)
		} else if port.Service == nil && port.State != nil {
			_, err = con.Exec("INSERT INTO service (hostid, port, protocol, service, state, product, version) VALUES (?,?,?,?,?,?,?)",
				hostid, port.Portid, port.Protocol, "", port.State.State, "", "")
		} else {
			_, err = con.Exec("INSERT INTO service (hostid, port, protocol) VALUES (?,?,?)", hostid, port.Portid, port.Protocol)
		}
		if err != nil {
			log.Fatal(err)
		}
	case err != nil:
		log.Fatal(err)
	default:
	}
}

func createServices(con *sql.DB, hostid int, hosts []nmap.XMLHost) {
	for _, host := range hosts {
		for _, ports := range host.Ports {
			for _, port := range ports.Port {
				queryServiceId(con, hostid, port)
			}
		}
	}
}

func listOpenPorts(hosts []nmap.XMLHost) string {
	var out string
	var sep string = ","
	for _, host := range hosts {
		for _, ports := range host.Ports {
			for _, port := range ports.Port {
				if port.State.State == "open" {
					out = strings.Join([]string{out, port.Portid}, sep)
				}
			}
		}
	}

	return strings.TrimPrefix(out, sep)
}

// Parse data from file in parameter
func parseAllXmlData(con *sql.DB, filepath string) {
	scans := make(Scans, 0, 100)
	scans.Load(filepath)
	for _, scan := range scans {
		if scan.Result.Nmap == nil {
			continue
		}
		s_reader := strings.NewReader(string(scan.Result.Nmap))
		v := nmap.XMLNmaprun{}
		decoder := xml.NewDecoder(s_reader)
		err := decoder.Decode(&v)
		if err != nil {
			log.Printf("parsing result of %v failed: %v", scan.Host, err)
			return
		}

		ports := listOpenPorts(v.Host)
		if ports != "" {
			fmt.Printf("%v;%v\n", scan.Host, ports)
		}

		// Saisie des données dans la base de données de SANOFI
		/*
			// v contient l'ensemble des données nmap de cet hôte.
			hostid, err := getNmapHostId(con, v.Host)
			if err != nil {
				log.Printf("Retrieving hostid for host %v failed: %v", v.Host, err)
				return
			}
			createServices(con, hostid, v.Host)
		*/

	}
}

func parseRun(c *cli.Context) {
	if !c.Args().Present() {
		log.Fatal("Need a json file to parse")
	}

	// Test de l'existence de la base de données. Si ce n'est pas le cas, la créer
	// TODO

	// connect to database
	con, err := sql.Open("mysql", c.String("user")+":"+c.String("password")+"@/"+c.String("database"))
	if err != nil {
		log.Fatal(err)
	}
	defer con.Close()

	parseAllXmlData(con, c.Args().First())
	/*
		if c.Bool("hostfile") == true {
			parseMultipleFiles(con, c.Args().First(), parseOneXmlFile)
		} else {
			parseOneXmlFile(con)
		}
	*/
}
