package nmap

import "fmt"

type Port struct {
	Protocol string
	Id       uint32
	State    string
	Scripts  []Script
}

type Script struct {
	Name     string
	Output   string
	Elements []Element
}

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

func (p Port) ToString() (out string) {
	out += fmt.Sprintf("Port %d/%s is %s\n", p.Id, p.Protocol, p.State)
	for _, script := range p.Scripts {
		out += fmt.Sprintf("  Script: %s\nOutput: %s\n", script.Name, script.Output)
	}
	return
}
