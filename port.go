package nmap

import (
	"fmt"
	"strings"
)

// Port represents nmap port information
type Port struct {
	Protocol string
	// Id is the port number
	Id      uint32
	State   string
	Scripts []Script
}

// Script are used for gathering nmap NSE script information
type Script struct {
	Name     string
	Output   string
	Elements []Element
}

// Elements are returned from NSE scripts
type Element struct {
	Key   string
	Value string
}

func (port rawPort) cleanPort() Port {
	output := Port{
		port.Protocol,
		port.Port,
		port.State.State,
		[]Script{},
	}
	for _, script := range port.Scripts {
		s := Script{script.Name, script.Output, []Element{}}
		for _, elem := range script.Elements {
			element := Element{elem.Key, elem.Value}
			s.Elements = append(s.Elements, element)
		}
		output.Scripts = append(output.Scripts, s)
	}

	return output
}

// ToString returns port information in a pretty-printed format
func (p Port) ToString() (out string) {
	out += fmt.Sprintf("Port %d/%s is %s\n", p.Id, p.Protocol, p.State)
	for _, script := range p.Scripts {
		output := ""
		for _, line := range strings.Split(script.Output, "\n") {
			output += fmt.Sprintf("      %s\n", line)
		}
		out += fmt.Sprintf("  Script: %s\n%s\n", script.Name, output)
	}
	return
}
