package nmap

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
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

	configHosts    []string
	configPorts    []uint16
	configTCPPorts []uint16
	configUDPPorts []uint16
	configOpts     []string
	configErr      error
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

// AddPortRange adds a list of ports where the first argument is the low bound
// (inclusive) on the range and the second argument is the upper bound
// (exclusive)
//
// E.x. AddPortRange(0, 1025) adds ports 1-1024 to the list
// TODO(t94j0): Make into actual nmap ranges. (-p1-1024)
func (s Scan) AddPortRange(lPort, hPort uint16) Scan {
	for i := lPort; i < hPort; i++ {
		s.configPorts = append(s.configPorts, i)
	}
	return s
}

// SetPorts sets the ports that wil be used
func (s Scan) SetPorts(ports ...uint16) Scan {
	s.configPorts = ports
	return s
}

// AddTCPPorts adds TCP-only ports. Similar to using `-pT:<port1>,<port2>...`
func (s Scan) AddTCPPorts(ports ...uint16) Scan {
	s.configTCPPorts = append(s.configTCPPorts, ports...)
	return s
}

// SetTCPPorts sets which TCP-only ports are used to scan
func (s Scan) SetTCPPorts(ports ...uint16) Scan {
	s.configTCPPorts = ports
	return s
}

// AddUDPPorts adds UDP-only ports. Similar to using `-pU:<port1>,<port2>...`
func (s Scan) AddUDPPorts(ports ...uint16) Scan {
	s.configUDPPorts = append(s.configUDPPorts, ports...)
	return s
}

// SetUDPPort sets which TCP-only ports are used to scan
func (s Scan) SetUDPPorts(ports ...uint16) Scan {
	s.configUDPPorts = ports
	return s
}

// AddFlags adds a list of flags to be used by nmap. Seperate flags by new
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

func (s Scan) SetFlags(flags ...string) Scan {
	s.configOpts = []string{}
	return s.AddFlags(flags...)
}

// Intense sets the options to use an "intense" scan. These are the same
// options as used in Zenmap's intense scan.
func (s Scan) Intense() Scan {
	return s.SetFlags("-A", "-T4")
}

// IntenseAllTCPPorts does an intense scan, but adds all TCP ports
func (s Scan) IntenseAllTCPPorts() Scan {
	return s.Intense().
		SetPorts().
		SetUDPPorts().
		SetTCPPorts().
		AddPortRange(1, 65535)
}

// Ping sets the `-sn` flag to only do a ping scan
func (s Scan) Ping() Scan {
	return s.SetFlags("-sn")
}

// Quick does a scan with timing at max and with the `-F` option
func (s Scan) Quick() Scan {
	return s.SetFlags("-T4", "-F")
}

// Run is used to scan hosts. The Scan object should be configured using
// specified Add* Set* functions.
//
// BUG(t94j0): The scan will sometimes segfault and theres no reason why
func (s Scan) Run() (output Scan, err error) {
	if s.configErr != nil {
		return s, s.configErr
	}

	args, err := s.CreateNmapArgs()
	if err != nil {
		return s, err
	}

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
