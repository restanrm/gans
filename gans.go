// GANS : Go Automated Nmap Scanner 
// This permit to launch a scanner and add adresses to be scanned.
package main

import (
	"github.com/codegangsta/cli"
	"github.com/restanrm/gans/cmd"
	"os"
)

func main() {
	app := cli.NewApp()
	app.Name = "Parns"
	app.Usage = "Command de gestion de scan d'hôte distants"
	app.Commands = []cli.Command{
		cmd.CmdScan,
		cmd.CmdRun,
	}
	app.Run(os.Args)
}
