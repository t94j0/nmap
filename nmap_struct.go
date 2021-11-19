package nmap

import "encoding/xml"

// Nmap is the root object that holds all data
type rawScan struct {
	xMLName xml.Name `xml:"nmaprun"`

	DisplayArgs string `xml:"args,attr"`
	StartTime   string `xml:"start,attr"`

	ScanInfo rawScanInfo `xml:"scaninfo"`
	Hosts    []rawHost   `xml:"host"`

	ScanHosts []string
	ScanPorts []int
	ScanOpts  []string
}

// ScanInfo holds data about what the was scanned
type rawScanInfo struct {
	xMLName xml.Name `xml:"scaninfo"`

	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices string `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
}

// Host holds the information about the port including what address it has and
// the information about the ports
type rawHost struct {
	xMLName xml.Name `xml:"host"`

	Status    rawStatus    `xml:"status"`
	Address   rawAddress   `xml:"address" json:"address"`
	Hostnames rawHostnames `xml:"hostnames"`
	Ports     rawPorts     `xml:"ports" json:"ports"`
}

// Status gives the status of the host
type rawStatus struct {
	xMLName xml.Name `xml:"status"`

	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// Address has the address of the server. This is only used when multiple hosts
// are scanned at the same time
type rawAddress struct {
	xMLName xml.Name `xml:"address"`

	Address     string `xml:"addr,attr"`
	AddressType string `xml:"addrtype,attr"`
}

// Hostnames are a list of hostnames
type rawHostnames struct {
	xMLName xml.Name `xml:"hostnames"`

	Hostnames []rawHostname `xml:"hostname"`
}

// Hostname is an entry that gives the user different hostnames that the IP
// may own
type rawHostname struct {
	xMLName xml.Name `xml:"hostname"`

	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// Ports is the array of ports
type rawPorts struct {
	xMLName xml.Name `xml:"ports"`

	Ports []rawPort `xml:"port"`
}

// Port has all of the information about the port in question
type rawPort struct {
	xMLName xml.Name `xml:"port"`

	Protocol string `xml:"protocol,attr" json:"protocol"`
	Port     uint32 `xml:"portid,attr" json:"port"`

	State   rawState    `xml:"state" json:"state"`
	Service rawService  `xml:"service"`
	Scripts []rawScript `xml:"script"`
}

// Status gives the status of "open, closed, filtered"
type rawState struct {
	xMLName xml.Name `xml:"state"`

	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// Service is the name of the service. Ex: "ssh, rdp, etc."
type rawService struct {
	xMLName xml.Name `xml:"service"`

	Name        string `xml:"name,attr"`
	Method      string `xml:"method,attr"`
	Product     string `xml:"product"`
	Fingerprint string `xml:"servicefp"`
}

// Script defines the output for various scripts
type rawScript struct {
	xMLName xml.Name `xml:"script"`

	Name   string `xml:"id,attr"`
	Output string `xml:"output,attr"`

	Elements []rawElement `xml:"elem"`
}

// Element defines an element of a script
type rawElement struct {
	xMLName xml.Name `xml:"elem"`

	Key string `xml:"key"`

	Value string
}

func parseXML(inputFile []byte) (*rawScan, error) {
	var result rawScan

	if err := xml.Unmarshal(inputFile, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
