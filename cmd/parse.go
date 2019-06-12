package cmd

import (
	"database/sql"
	"encoding/xml"
	"errors"
	"fmt"
	"log"

	"github.com/codegangsta/cli"
	_ "github.com/go-sql-driver/mysql"
	"github.com/restanrm/gans/nmap"
	//"net"
	"strconv"
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
			Value: "defaultPassword",
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

// Draft de structure de base de données
// Cette structure correspond a ce qui se trouve dans la base de données locale
type Service struct {
	Name,
	Version,
	Product,
	OsType string
}

func (s Service) String() string {
	return fmt.Sprintf("%v, %v, %v", s.Name, s.Version, s.Product)
}

type Port struct {
	Number   int
	Protocol string
	Status   string
	Service  Service
}

func (p Port) String() string {
	// affiche le résultat si le port est ouvert.
	if p.Status == "open" {
		return fmt.Sprintf("  %-6v: %v; %v, %v\n", p.Number, p.Status, p.Protocol, p.Service)
	}
	return ""
}

type Host struct {
	Address string
	Status  string
	Os      string
	Ports   []Port
}

func (h Host) String() string {
	var out string = ""
	out = fmt.Sprintf("%v: %v - %v\n", h.Address, h.Status, h.Os)
	for _, port := range h.Ports {
		out += port.String()
	}
	return out
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

func listPorts(hosts []nmap.XMLHost) []Port {
	t_ports := make([]Port, 0, 10)
	for _, host := range hosts {
		for _, ports := range host.Ports {
			for _, port := range ports.Port {
				var service Service
				if port.Service != nil {
					service = Service{
						Name:    port.Service.Name,
						Version: port.Service.Version,
						Product: port.Service.Product,
						OsType:  port.Service.Ostype,
					}
				}
				p_id, _ := strconv.Atoi(port.Portid)
				t_ports = append(t_ports, Port{
					Number:   p_id,
					Protocol: port.Protocol,
					Status:   port.State.State,
					Service:  service})
			}
		}
	}
	return t_ports
}

func get_status(hosts []nmap.XMLHost) string {
	for _, host := range hosts {
		for _, statuses := range host.Status {
			return statuses.State
		}
	}
	return ""
}

func get_os(hosts []nmap.XMLHost) string {
	for _, host := range hosts {
		for _, oses := range host.Os {
			for _, osmatch := range oses.Osmatch {
				return osmatch.Name
			}
		}
	}
	return ""
}

// Parse data from file in parameter
func parseAllXmlData(filepath string) {
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

		host := Host{
			Address: scan.Host,
			Status:  get_status(v.Host),
			Os:      get_os(v.Host),
			Ports:   listPorts(v.Host)}

		fmt.Print(host)
	}
}

func parseRun(c *cli.Context) {
	if !c.Args().Present() {
		log.Fatal("Need a json file to parse")
	}
	parseAllXmlData(c.Args().First())
}
