package nmap

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strconv"
	"strings"
)

// DisallowedFlagError is thrown when a disallowed flag is used. A list of
// disallowed flags can be seen in the `DisallowedFlags` variable
type DisallowedFlagError struct {
	Flag string
}

// Error returns the flag string
func (f *DisallowedFlagError) Error() string {
	return "Flag '" + f.Flag + "' is not allowed"
}

// DisallowedFlags is a list of flags that will break the nmap library's
// ability to parse the output
var DisallowedFlags = []string{"-oN", "-oX", "-oG", "-oA"}

// Scan holds one nmap scan. It can be rescanned, diff'ed, and parsed for hosts
type Scan struct {
	DisplayArgs string
	Hosts       map[string]Host

	configHosts []string
	configPorts []uint16
	configOpts  []string
	configErr   error
}

func (scan rawScan) cleanScan(s Scan) Scan {
	s.DisplayArgs = scan.DisplayArgs
	for _, host := range scan.Hosts {
		newHost := host.cleanHost()
		newHost.parentScan = &s
		s.Hosts[newHost.Address] = newHost
	}

	return s
}

// Init initializes a scan object. This is the easiest way to create a Scan
// object. If you are trying to create a Scan object by hand, make sure to
// instantiate the Hosts map
func Init() Scan {
	scan := Scan{}
	scan.Hosts = make(map[string]Host, 0)
	return scan
}

// AddHosts adds a list of hosts to the list of hosts to be scanned
func (s Scan) AddHosts(hosts ...string) Scan {
	s.configHosts = append(s.configHosts, hosts...)
	return s
}

// SetHosts sets the hosts that will be scanned
func (s Scan) SetHosts(hosts ...string) Scan {
	s.configHosts = hosts
	return s
}

// AddPorts appends a list of ports to the list of ports to be scanned
func (s Scan) AddPorts(ports ...uint16) Scan {
	s.configPorts = append(s.configPorts, ports...)
	return s
}

// SetPorts sets the ports that wil be used
func (s Scan) SetPorts(ports ...uint16) Scan {
	s.configPorts = ports
	return s
}

// AddFlag adds a list of flags to be used by nmap. Seperate flags by new
// arguments. The order of the flag is kept, so when using flags that require
// file names, seperate it by using multiple arguments.
//
// Use the DisallowedFlags variable to guide you on which flags are not allowed
// to be used.
func (s Scan) AddFlags(flags ...string) Scan {
	for _, flag := range flags {
		if strings.Contains(flag, " ") {
			s.configErr = errors.New("Flags must not have spaces in them")
			return s
		}
		for _, df := range DisallowedFlags {
			if flag == df {
				s.configErr = &DisallowedFlagError{df}
				return s
			}
		}
	}

	s.configOpts = append(s.configOpts, flags...)
	return s
}

func (s Scan) createNmapArgs() []string {
	// Parse arguments
	args := []string{"-oX", "-"}

	portList := ""
	if len(s.configPorts) != 0 {
		for _, port := range s.configPorts {
			portList += strconv.FormatUint(uint64(port), 10) + ","
		}
	}

	args = append(args, s.configOpts...)
	if portList != "" {
		args = append(args, "-p", portList)
	}
	if len(s.configHosts) == 0 {
		s.configErr = errors.New("No hosts added")
	}
	args = append(args, s.configHosts...)

	return args
}

// Run is used to scan hosts. The Scan object should be configured using
// specified Add* Set* functions.
func (s Scan) Run() (Scan, error) {
	if s.configErr != nil {
		return s, s.configErr
	}

	args := s.createNmapArgs()

	// Find path for nmap binary
	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		return s, err
	}

	cmd := exec.Command(nmapPath, args...)

	// Configure output pipes
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return s, err
	}

	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return s, err
	}

	// Start command
	if err := cmd.Start(); err != nil {
		return s, err
	}

	// Read output
	stdout, err := ioutil.ReadAll(outPipe)
	if err != nil {
		return s, err
	}

	stderr, err := ioutil.ReadAll(errPipe)
	if err != nil {
		return s, err
	}

	// Wait on command to be finished
	if err := cmd.Wait(); err != nil {
		fmt.Println(err)
		return s, errors.New(err.Error() + "\n" + string(stderr))
	}

	// Parse command output
	rawScan, err := parseXML(stdout)
	if err != nil {
		return s, err
	}

	scan := rawScan.cleanScan(s)

	return scan, nil
}

// ToString returns the list of hosts into a pretty-printed format
func (s Scan) ToString() (out string) {
	for _, host := range s.Hosts {
		out += fmt.Sprintf("%s\n", host.ToString())
	}
	return
}
