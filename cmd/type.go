package cmd

import (
	"bytes"
	"encoding/json"
	"os"
)

const (
	null = iota
	icmp_in_progress
	nmap_in_progress
	finished
	failed
)

type Scan struct {
	Host   string
	Status int
	Result Result
}

func (s *Scan) Equal(d *Scan) bool {
	return s.Host == d.Host && s.Status == d.Status && s.Result.Equal(&d.Result)
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
