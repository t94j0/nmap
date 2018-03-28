package nmap

import (
	"errors"
	"strconv"
	"strings"

	"github.com/t94j0/array"
)

// CreateNmapArgs takes a Scan object and returns a list of strings that map to
// arguments for an nmap scan.
func (s Scan) CreateNmapArgs() ([]string, error) {
	// Parse arguments
	args := []string{"-oX", "-"}
	const seperator string = ","

	// Set up ports
	portList := ""
	portList += strings.Join(uint16ListToStringList(s.configPorts), seperator)
	if len(s.configUDPPorts) != 0 {
		if portList != "" {
			portList += ","
		}
		portList += "U:"
	}
	portList += strings.Join(uint16ListToStringList(s.configUDPPorts), seperator)
	if len(s.configTCPPorts) != 0 {
		if portList != "" {
			portList += ","
		}
		portList += "T:"
	}
	portList += strings.Join(uint16ListToStringList(s.configTCPPorts), seperator)

	// Check to make sure all TCP/UDP flags are correct
	// Check TCP flags
	tcpOptions := []string{"-sS", "-sT", "-sA", "-sW", "-sM"}
	iflagI, err := array.Intersection(tcpOptions, s.configOpts)
	if err != nil {
		return []string{}, err
	}
	iflag := iflagI.([]string)
	if len(iflag) == 0 {
		s.configOpts = append(s.configOpts, tcpOptions[0])
	}

	// Check UDP flag
	if !array.In("-sU", s.configOpts) {
		s.configOpts = append(s.configOpts, "-sU")
	}

	// Append arguments
	args = append(args, s.configOpts...)

	// Append port list
	if portList != "" {
		args = append(args, "-p"+portList)
	}
	// Append hosts
	if len(s.configHosts) == 0 {
		s.configErr = errors.New("No hosts added")
	}
	args = append(args, s.configHosts...)

	return args, nil
}

// uint16ListToStringList is used to reduce lines for joining strings in
// the CreateNmapArgs function
func uint16ListToStringList(source []uint16) (o []string) {
	for _, s := range source {
		o = append(o, strconv.FormatUint(uint64(s), 10))
	}
	return
}
