package nmap

import (
	"fmt"
	"strings"
)

// Host declares host information
type Host struct {
	parentScan *Scan

	State       string
	Address     string
	AddressType string
	Hostnames   []Hostname
	Ports       []Port
}

// Hostname declares the hostname and type
type Hostname struct {
	Name string
	Type string
}

// cleanHost is used to conver from the rawHost format to a more usable format
func (host rawHost) cleanHost() Host {
	output := Host{
		nil,
		host.Status.State,
		host.Address.Address,
		host.Address.AddressType,
		[]Hostname{},
		[]Port{},
	}

	for _, hostname := range host.Hostnames.Hostnames {
		output.Hostnames = append(output.Hostnames,
			Hostname{hostname.Name, hostname.Type})
	}
	for _, port := range host.Ports.Ports {
		output.Ports = append(output.Ports, port.cleanPort())
	}

	return output
}

// GetHost will get a specified host by either hostname or ip. The first
// return value is the host, if it was found. The second return value is the
// wether the host was found or not
func (s Scan) GetHost(hostTarget string) (target Host, exists bool) {
	target, ok := s.Hosts[hostTarget]
	if ok {
		return target, true
	}

	for _, host := range s.Hosts {
		for _, hostname := range host.Hostnames {
			if hostname.Name == hostTarget {
				return host, true
			}
		}
	}

	return Host{}, false
}

// Rescan the target. Normally used for finding differences between scans
// at two points in time.
func (h Host) Rescan() (scan Scan) {
	return Init().
		AddPorts(h.parentScan.configPorts...).
		AddHosts(h.Address).
		AddFlags(h.parentScan.configOpts...)
}

// Diff gets the difference between the the target host and the argument host.
//The first returned value is the added ports and the second returned value is
// the removed ports.
//
// BUG(t94j0): Make diff'ing more efficient. (O(2) right now)
func (h Host) Diff(altHost Host) (added []Port, removed []Port) {
	targetPorts := h.Ports
	altPorts := altHost.Ports

	for _, altPort := range altPorts {
		inTarget := false
		for _, targetPort := range targetPorts {
			if targetPort.ID == altPort.ID &&
				targetPort.State == "open" && altPort.State == "open" {
				inTarget = true
			}
		}

		if !inTarget && altPort.State == "open" {
			added = append(added, altPort)
		}
	}

	for _, targetPort := range targetPorts {
		inAlt := false
		for _, altPort := range altPorts {
			if targetPort.ID == altPort.ID &&
				targetPort.State == "open" && altPort.State == "open" {
				inAlt = true
			}
		}

		if !inAlt && targetPort.State == "open" {
			removed = append(removed, targetPort)
		}
	}

	return
}

// ToString converts the host into a nicely formatted string
func (h Host) ToString() (out string) {
	out += fmt.Sprintf("%s is %s\n", h.Address, h.State)
	if len(h.Hostnames) != 0 {
		out += "Hostnames:\n"
		for _, hostname := range h.Hostnames {
			out += fmt.Sprintf("  %s/%s\n", hostname.Name, hostname.Type)
		}
	}
	if len(h.Ports) != 0 {
		out += "Ports:\n"
		for _, port := range h.Ports {
			for _, line := range strings.Split(port.ToString(), "\n") {
				if line != "" {
					out += fmt.Sprintf("  %s\n", line)
				}
			}
		}
	}
	return
}
