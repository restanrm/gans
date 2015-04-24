package cmd

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"time"
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
			s.Status = nmap_failed
		}
		result <- tmp
	}()
	for end := false; !end; {
		select {
		case s.Result.Nmap = <-result:
			if s.Status != nmap_failed {
				s.Status = nmap_done
			}
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
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	/*
		for scan := range s {
			err = enc.Encode(scan)
			if err != nil {
				return err
			}
		}
	*/
	enc.Encode(s)
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
