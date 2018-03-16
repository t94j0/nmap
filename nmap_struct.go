package nmap

import "encoding/xml"

// Nmap is the root object that holds all data
type RawScan struct {
	xMLName xml.Name `xml:"nmaprun"`

	DisplayArgs string `xml:"args,attr"`
	StartTime   string `xml:"start,attr"`

	ScanInfo RawScanInfo `xml:"scaninfo"`
	Hosts    []RawHost   `xml:"host"`

	ScanHosts []string
	ScanPorts []int
	ScanOpts  []string
}

// ScanInfo holds data about what the was scanned
type RawScanInfo struct {
	xMLName xml.Name `xml:"scaninfo"`

	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices string `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
}

// Host holds the information about the port including what address it has and
// the information about the ports
type RawHost struct {
	xMLName xml.Name `xml:"host"`

	Status    RawStatus    `xml:"status"`
	Address   RawAddress   `xml:"address" json:"address"`
	Hostnames RawHostnames `xml:"hostnames"`
	Ports     RawPorts     `xml:"ports" json:"ports"`
}

// Status gives the status of the host
type RawStatus struct {
	xMLName xml.Name `xml:"status"`

	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// Address has the address of the server. This is only used when multiple hosts
// are scanned at the same time
type RawAddress struct {
	xMLName xml.Name `xml:"address"`

	Address     string `xml:"addr,attr"`
	AddressType string `xml:"addrtype,attr"`
}

// Hostnames are a list of hostnames
type RawHostnames struct {
	xMLName xml.Name `xml:"hostnames"`

	Hostnames []RawHostname `xml:"hostname"`
}

// Hostname is an entry that gives the user different hostnames that the IP
// may own
type RawHostname struct {
	xMLName xml.Name `xml:"hostname"`

	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// Ports is the array of ports
type RawPorts struct {
	xMLName xml.Name `xml:"ports"`

	Ports []RawPort `xml:"port"`
}

// Port has all of the information about the port in question
type RawPort struct {
	xMLName xml.Name `xml:"port"`

	Protocol string `xml:"protocol,attr" json:"protocol"`
	Port     uint32 `xml:"portid,attr" json:"port"`

	State   RawState    `xml:"state" json:"state"`
	Service RawService  `xml:"service"`
	Scripts []RawScript `xml:"script"`
}

// Status gives the status of "open, closed, filtered"
type RawState struct {
	xMLName xml.Name `xml:"state"`

	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// Service is the name of the service. Ex: "ssh, rdp, etc."
type RawService struct {
	xMLName xml.Name `xml:"service"`

	Name        string `xml:"name,attr"`
	Product     string `xml:"product"`
	Fingerprint string `xml:"servicefp"`
}

// Script defines the output for various scripts
type RawScript struct {
	xMLName xml.Name `xml:"script"`

	Name   string `xml:"id,attr"`
	Output string `xml:"output,attr"`

	Elements []RawElement `xml:"elem"`
}

// Element defines an element of a script
type RawElement struct {
	xMLName xml.Name `xml:"elem"`

	Key string `xml:"key"`

	Value string
}

func parseXML(inputFile []byte) (*RawScan, error) {
	var result RawScan

	if err := xml.Unmarshal(inputFile, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
