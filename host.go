package nmap

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
// ex: Hostname{maxh.io, PTR}
// ex: Hostname{maxh.io, user}
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

// GetHost will get a specified host by either hostname or ip
func (s Scan) GetHost(hostTarget string) Host {
	for _, host := range s.Hosts {
		if host.Address == hostTarget {
			return host
		}
		for _, hostname := range host.Hostnames {
			if hostname.Name == hostTarget {
				return host
			}
		}
	}

	return Host{}
}

// Rescan the target. Normally used for finding differences between scans
// at two points in time.
func (host Host) Rescan() Scan {
	newScan := Init().
		AddPorts(host.parentScan.configPorts...).
		AddHost(host.Address).
		AddFlags(host.parentScan.configOpts...)

	return newScan
}

// Diff gets the difference between the the target host and the argument host.
//The first returned value is the added ports and the second returned value is
// the removed ports.
// TODO: Make the logic a bit better
func (h Host) Diff(altHost Host) ([]Port, []Port) {
	var addedPorts []Port
	var removedPorts []Port

	targetPorts := h.Ports
	altPorts := altHost.Ports

	i := 0
	j := 0
	for i < len(targetPorts) && j < len(altPorts) {
		// Make sure we only check which ports are open
		if targetPorts[i].State != "open" {
			i++
			continue
		}
		if altPorts[j].State != "open" {
			j++
			continue
		}
		// Only works if ports are in sorted order
		if targetPorts[i].Id < altPorts[j].Id {
			addedPorts = append(addedPorts, targetPorts[i])
			i++
		} else if targetPorts[i].Id > altPorts[j].Id {
			removedPorts = append(removedPorts, altPorts[j])
			j++
		} else {
			i++
			j++
		}

		// Finish up
		if i == len(targetPorts) && j != len(altPorts) {
			for j < len(altPorts) {
				removedPorts = append(removedPorts, altPorts[j])
				j++
			}
		}
		if j == len(altPorts) && i != len(targetPorts) {
			for i < len(targetPorts) {
				addedPorts = append(addedPorts, targetPorts[i])
				i++
			}
		}
	}

	return addedPorts, removedPorts
}
