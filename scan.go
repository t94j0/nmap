package nmap

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strconv"
	"strings"
)

type DisallowedFlagError struct {
	Flag string
}

func (f *DisallowedFlagError) Error() string {
	return "Flag '" + f.Flag + "' is not allowed"
}

var DisallowedFlags = []string{"-oN", "-oX", "-oG", "-oA"}

// Scan holds one nmap scan. It can be rescanned, diff'ed, and parsed for hosts
type Scan struct {
	DisplayArgs string
	Hosts       []Host

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
		s.Hosts = append(s.Hosts, newHost)
	}

	return s
}

// Init initializes a scan object. This must be called when starting a scan
func Init() Scan {
	return Scan{}
}

// AddHost adds one host to the list of hosts to be scanned
func (s Scan) AddHost(host string) Scan {
	s.configHosts = append(s.configHosts, host)
	return s
}

// SetHost sets a single host to be the target of scanning
func (s Scan) SetHost(host string) Scan {
	s.configHosts = []string{host}
	return s
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

// AddPorts appends port to the list of ports to be scanned
func (s Scan) AddPort(port uint16) Scan {
	s.configPorts = append(s.configPorts, port)
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
	args = append(args, s.configHosts...)

	return args
}

// RunScan is used to scan hosts with a list of hosts, ports, and nmap flags
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
		return s, errors.New(err.Error() + "\n" +
			string(stderr) + "\n" + string(stdout))
	}

	// Parse command output
	rawScan, err := parseXML(stdout)
	if err != nil {
		return s, err
	}

	scan := rawScan.cleanScan(s)

	return scan, nil
}
