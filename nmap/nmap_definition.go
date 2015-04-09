package nmap

import (
	"encoding/xml"
)

type XMLTable struct {
	XMLName xml.Name `xml:"table"`
	Key	string	`xml:"key,attr,omitempty"`
	Table	[]XMLTable	`xml:"table,omitempty"`
	Elem	[]XMLElem	`xml:"elem,omitempty"`
}

type XMLOsclass struct {
	XMLName xml.Name `xml:"osclass"`
	Osgen	string	`xml:"osgen,attr,omitempty"`
	Vendor	string	`xml:"vendor,attr"`
	Accuracy	string	`xml:"accuracy,attr"`
	Type	string	`xml:"type,attr,omitempty"`
	Osfamily	string	`xml:"osfamily,attr"`
	Cpe	[]XMLCpe	`xml:"cpe,omitempty"`
}

type XMLTrace struct {
	XMLName xml.Name `xml:"trace"`
	Proto	string	`xml:"proto,attr,omitempty"`
	Port	string	`xml:"port,attr,omitempty"`
	Hop	[]XMLHop	`xml:"hop,omitempty"`
}

type XMLTcptssequence struct {
	XMLName xml.Name `xml:"tcptssequence"`
	Values	string	`xml:"values,attr,omitempty"`
	Class	string	`xml:"class,attr"`
}

type XMLUptime struct {
	XMLName xml.Name `xml:"uptime"`
	Lastboot	string	`xml:"lastboot,attr,omitempty"`
	Seconds	string	`xml:"seconds,attr"`
}

type XMLPorts struct {
	XMLName xml.Name `xml:"ports"`
	Port	[]XMLPort	`xml:"port,omitempty"`
	Extraports	[]XMLExtraports	`xml:"extraports,omitempty"`
}

type XMLStatus struct {
	XMLName xml.Name `xml:"status"`
	ReasonTtl	string	`xml:"reason_ttl,attr"`
	Reason	string	`xml:"reason,attr"`
	State	string	`xml:"state,attr"`
}

type XMLOsmatch struct {
	XMLName xml.Name `xml:"osmatch"`
	Line	string	`xml:"line,attr"`
	Accuracy	string	`xml:"accuracy,attr"`
	Name	string	`xml:"name,attr"`
	Osclass	[]XMLOsclass	`xml:"osclass,omitempty"`
}

type XMLPortused struct {
	XMLName xml.Name `xml:"portused"`
	Proto	string	`xml:"proto,attr"`
	State	string	`xml:"state,attr"`
	Portid	string	`xml:"portid,attr"`
}

type XMLOs struct {
	XMLName xml.Name `xml:"os"`
	Portused	[]XMLPortused	`xml:"portused,omitempty"`
	Osmatch	[]XMLOsmatch	`xml:"osmatch,omitempty"`
	Osfingerprint	[]XMLOsfingerprint	`xml:"osfingerprint,omitempty"`
}

type XMLTcpsequence struct {
	XMLName xml.Name `xml:"tcpsequence"`
	Difficulty	string	`xml:"difficulty,attr"`
	Values	string	`xml:"values,attr"`
	Index	string	`xml:"index,attr"`
}

type XMLTimes struct {
	XMLName xml.Name `xml:"times"`
	Srtt	string	`xml:"srtt,attr"`
	Rttvar	string	`xml:"rttvar,attr"`
	To	string	`xml:"to,attr"`
}

type XMLOsfingerprint struct {
	XMLName xml.Name `xml:"osfingerprint"`
	Fingerprint	string	`xml:"fingerprint,attr"`
}

type XMLOutput struct {
	XMLName xml.Name `xml:"output"`
	Type	string	`xml:"type,attr,omitempty"`
	Value	string	`xml:",chardata"`
}

type XMLPrescript struct {
	XMLName xml.Name `xml:"prescript"`
	Script	[]XMLScript	`xml:"script"`
}

type XMLTaskend struct {
	XMLName xml.Name `xml:"taskend"`
	Extrainfo	string	`xml:"extrainfo,attr,omitempty"`
	Time	string	`xml:"time,attr"`
	Task	string	`xml:"task,attr"`
}

type XMLTaskprogress struct {
	XMLName xml.Name `xml:"taskprogress"`
	Task	string	`xml:"task,attr"`
	Etc	string	`xml:"etc,attr"`
	Time	string	`xml:"time,attr"`
	Remaining	string	`xml:"remaining,attr"`
	Percent	string	`xml:"percent,attr"`
}

type XMLTaskbegin struct {
	XMLName xml.Name `xml:"taskbegin"`
	Time	string	`xml:"time,attr"`
	Task	string	`xml:"task,attr"`
	Extrainfo	string	`xml:"extrainfo,attr,omitempty"`
}

type XMLTarget struct {
	XMLName xml.Name `xml:"target"`
	Specification	string	`xml:"specification,attr"`
	Reason	string	`xml:"reason,attr,omitempty"`
	Status	string	`xml:"status,attr,omitempty"`
}

type XMLPostscript struct {
	XMLName xml.Name `xml:"postscript"`
	Script	[]XMLScript	`xml:"script"`
}

type XMLSmurf struct {
	XMLName xml.Name `xml:"smurf"`
	Responses	string	`xml:"responses,attr"`
}

type XMLService struct {
	XMLName xml.Name `xml:"service"`
	Ostype	string	`xml:"ostype,attr,omitempty"`
	Servicefp	string	`xml:"servicefp,attr,omitempty"`
	Conf	string	`xml:"conf,attr"`
	Hostname	string	`xml:"hostname,attr,omitempty"`
	Proto	string	`xml:"proto,attr,omitempty"`
	Version	string	`xml:"version,attr,omitempty"`
	Lowver	string	`xml:"lowver,attr,omitempty"`
	Product	string	`xml:"product,attr,omitempty"`
	Name	string	`xml:"name,attr"`
	Devicetype	string	`xml:"devicetype,attr,omitempty"`
	Method	string	`xml:"method,attr"`
	Rpcnum	string	`xml:"rpcnum,attr,omitempty"`
	Tunnel	string	`xml:"tunnel,attr,omitempty"`
	Extrainfo	string	`xml:"extrainfo,attr,omitempty"`
	Highver	string	`xml:"highver,attr,omitempty"`
	Cpe	[]XMLCpe	`xml:"cpe,omitempty"`
}

type XMLOwner struct {
	XMLName xml.Name `xml:"owner"`
	Name	string	`xml:"name,attr"`
}

type XMLState struct {
	XMLName xml.Name `xml:"state"`
	State	string	`xml:"state,attr"`
	ReasonIp	string	`xml:"reason_ip,attr,omitempty"`
	ReasonTtl	string	`xml:"reason_ttl,attr"`
	Reason	string	`xml:"reason,attr"`
}

type XMLPort struct {
	XMLName xml.Name `xml:"port"`
	Protocol	string	`xml:"protocol,attr"`
	Portid	string	`xml:"portid,attr"`
	Service	*XMLService	`xml:"service,omitempty"`
	Owner	*XMLOwner	`xml:"owner,omitempty"`
	State	*XMLState	`xml:"state"`
	Script	[]XMLScript	`xml:"script,omitempty"`
}


type XMLRunstats struct {
	XMLName xml.Name `xml:"runstats"`
	Finished	*XMLFinished	`xml:"finished"`
	Hosts	*XMLHosts	`xml:"hosts"`
}

type XMLVerbose struct {
	XMLName xml.Name `xml:"verbose"`
	Level	string	`xml:"level,attr,omitempty"`
}

type XMLScaninfo struct {
	XMLName xml.Name `xml:"scaninfo"`
	Services	string	`xml:"services,attr"`
	Protocol	string	`xml:"protocol,attr"`
	Numservices	string	`xml:"numservices,attr"`
	Scanflags	string	`xml:"scanflags,attr,omitempty"`
	Type	string	`xml:"type,attr"`
}

type XMLNmaprun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Args	string	`xml:"args,attr,omitempty"`
	Start	string	`xml:"start,attr,omitempty"`
	Xmloutputversion	string	`xml:"xmloutputversion,attr"`
	Scanner	string	`xml:"scanner,attr"`
	Version	string	`xml:"version,attr"`
	ProfileName	string	`xml:"profile_name,attr,omitempty"`
	Startstr	string	`xml:"startstr,attr,omitempty"`
	Verbose	*XMLVerbose	`xml:"verbose"`
	Scaninfo	[]XMLScaninfo	`xml:"scaninfo,omitempty"`
	Runstats	*XMLRunstats	`xml:"runstats"`
	Debugging	*XMLDebugging	`xml:"debugging"`
	Target	[]XMLTarget	`xml:"target,omitempty"`
	Taskbegin	[]XMLTaskbegin	`xml:"taskbegin,omitempty"`
	Taskprogress	[]XMLTaskprogress	`xml:"taskprogress,omitempty"`
	Taskend	[]XMLTaskend	`xml:"taskend,omitempty"`
	Prescript	[]XMLPrescript	`xml:"prescript,omitempty"`
	Postscript	[]XMLPostscript	`xml:"postscript,omitempty"`
	Host	[]XMLHost	`xml:"host,omitempty"`
	Output	[]XMLOutput	`xml:"output,omitempty"`
}

type XMLIpidsequence struct {
	XMLName xml.Name `xml:"ipidsequence"`
	Class	string	`xml:"class,attr"`
	Values	string	`xml:"values,attr"`
}

type XMLHosts struct {
	XMLName xml.Name `xml:"hosts"`
	Total	string	`xml:"total,attr"`
	Down	string	`xml:"down,attr,omitempty"`
	Up	string	`xml:"up,attr,omitempty"`
}

type XMLScript struct {
	XMLName xml.Name `xml:"script"`
	Id	string	`xml:"id,attr"`
	Output	string	`xml:"output,attr"`
	Table	[]XMLTable	`xml:"table,omitempty"`
	Elem	[]XMLElem	`xml:"elem,omitempty"`
}

type XMLHostscript struct {
	XMLName xml.Name `xml:"hostscript"`
	Script	[]XMLScript	`xml:"script"`
}

type XMLHostnames struct {
	XMLName xml.Name `xml:"hostnames"`
	Hostname	[]XMLHostname	`xml:"hostname,omitempty"`
}

type XMLHostname struct {
	XMLName xml.Name `xml:"hostname"`
	Name	string	`xml:"name,attr,omitempty"`
	Type	string	`xml:"type,attr,omitempty"`
}

type XMLHost struct {
	XMLName xml.Name `xml:"host"`
	Comment	string	`xml:"comment,attr,omitempty"`
	Endtime	string	`xml:"endtime,attr,omitempty"`
	Starttime	string	`xml:"starttime,attr,omitempty"`
	Status	[]XMLStatus	`xml:"status,omitempty"`
	Address	[]XMLAddress	`xml:"address,omitempty"`
	Hostnames	[]XMLHostnames	`xml:"hostnames,omitempty"`
	Smurf	[]XMLSmurf	`xml:"smurf,omitempty"`
	Ports	[]XMLPorts	`xml:"ports,omitempty"`
	Os	[]XMLOs	`xml:"os,omitempty"`
	Distance	[]XMLDistance	`xml:"distance,omitempty"`
	Uptime	[]XMLUptime	`xml:"uptime,omitempty"`
	Tcpsequence	[]XMLTcpsequence	`xml:"tcpsequence,omitempty"`
	Ipidsequence	[]XMLIpidsequence	`xml:"ipidsequence,omitempty"`
	Tcptssequence	[]XMLTcptssequence	`xml:"tcptssequence,omitempty"`
	Hostscript	[]XMLHostscript	`xml:"hostscript,omitempty"`
	Trace	[]XMLTrace	`xml:"trace,omitempty"`
	Times	[]XMLTimes	`xml:"times,omitempty"`
}

type XMLHop struct {
	XMLName xml.Name `xml:"hop"`
	Ttl	string	`xml:"ttl,attr"`
	Rtt	string	`xml:"rtt,attr,omitempty"`
	Host	string	`xml:"host,attr,omitempty"`
	Ipaddr	string	`xml:"ipaddr,attr,omitempty"`
}

type XMLFinished struct {
	XMLName xml.Name `xml:"finished"`
	Timestr	string	`xml:"timestr,attr,omitempty"`
	Exit	string	`xml:"exit,attr,omitempty"`
	Time	string	`xml:"time,attr"`
	Summary	string	`xml:"summary,attr,omitempty"`
	Elapsed	string	`xml:"elapsed,attr"`
	Errormsg	string	`xml:"errormsg,attr,omitempty"`
}

type XMLExtrareasons struct {
	XMLName xml.Name `xml:"extrareasons"`
	Reason	string	`xml:"reason,attr"`
	Count	string	`xml:"count,attr"`
}

type XMLExtraports struct {
	XMLName xml.Name `xml:"extraports"`
	Count	string	`xml:"count,attr"`
	State	string	`xml:"state,attr"`
	Extrareasons	[]XMLExtrareasons	`xml:"extrareasons,omitempty"`
}

type XMLElem struct {
	XMLName xml.Name `xml:"elem"`
	Key	string	`xml:"key,attr,omitempty"`
	Value	string	`xml:",chardata"`
}

type XMLDistance struct {
	XMLName xml.Name `xml:"distance"`
	Value	string	`xml:"value,attr"`
}

type XMLDebugging struct {
	XMLName xml.Name `xml:"debugging"`
	Level	string	`xml:"level,attr,omitempty"`
}

type XMLCpe struct {
	XMLName xml.Name `xml:"cpe"`
	Value	string	`xml:",chardata"`
}

type XMLAddress struct {
	XMLName xml.Name `xml:"address"`
	Addrtype	string	`xml:"addrtype,attr,omitempty"`
	Vendor	string	`xml:"vendor,attr,omitempty"`
	Addr	string	`xml:"addr,attr"`
}

