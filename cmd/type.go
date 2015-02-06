package cmd

const (
	null = iota
	icmp_in_progress
	icmp_finished
	nmap_in_progress
	nmap_finished
)

type Scan struct {
	Host   string
	Status int
	Result Result
}

type Result struct {
	Nmap []byte
	Icmp []byte
}
