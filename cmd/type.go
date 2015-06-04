package cmd

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path"
)

const (
	null = iota
	icmp_in_progress
	icmp_failed
	icmp_done
	nmap_in_progress
	nmap_failed
	nmap_done
	finished
)

type Scan struct {
	Host   string
	Status int
	Result Result
}

func (s *Scan) Equal(d *Scan) bool {
	return s.Host == d.Host && s.Status == d.Status && s.Result.Equal(&d.Result)
}

func (s *Scan) DoPing() {
	s.Status = icmp_in_progress
	cmd := exec.Command("/bin/ping", "-c", "2", s.Host)
	var err error
	s.Result.Icmp, err = cmd.Output()
	if err != nil {
		log.Printf("Failed to ping destination %s: %s", s.Host, err)
		s.Result.Icmp = []byte("Failed")
		// bypass icmp_failed for now, icmp failed in case host is not responding
		//s.Status = icmp_failed
	} else {
		s.Status = icmp_done
	}
}

func (s *Scan) DoNmap() {
	if s.Status == icmp_failed {
		return
	}
	s.Status = nmap_in_progress
	cmd := exec.Command("nmap",
		"-n",
		"-T3",      // Temporisation 3 moyen (0 lent, 5 rapide)
		"-sS",      // SYN scan
		"-sV",      // Detection de version
		"-oX", "-", // Sortie en XML
		"--verbose", // Plus de verbosité
		"-O",        // Detection de l'OS
		"-p -",      // Tous les ports réseau
		s.Host)
	res, err := cmd.Output()
	s.Result.Nmap = res
	if err != nil {
		log.Printf("Failed to nmap destination %s: %s", s.Host, err)
		s.Status = nmap_failed
	} else {
		log.Printf("Finished Work for %v\n", s.Host)
		s.Status = nmap_done
	}
}

type Result struct {
	Nmap []byte
	Icmp []byte
}

func (s *Result) Equal(d *Result) bool {
	return bytes.Equal(s.Nmap, d.Nmap) && bytes.Equal(s.Icmp, d.Icmp)
}

type Scans []Scan

// save all scan structure to filepath in JSON format
func (s *Scans) Save(filepath string) error {
	var err error
	var backup_path string = path.Clean("." + filepath)
	file, err := os.Create(backup_path)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.Encode(s)
	file.Close()
	err = os.Rename(backup_path, filepath)
	if err != nil {
		return err
	}
	return nil
}

// load data from source file
func (s *Scans) Load(filepath string) error {
	var err error
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()
	dec := json.NewDecoder(file)
	err = dec.Decode(s)
	if err != nil {
		return err
	}
	return nil
}
