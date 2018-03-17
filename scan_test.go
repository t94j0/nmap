package nmap

import "github.com/t94j0/nmap"

func ExampleRun() {
	scan, _ := nmap.Init().
		AddHosts("maxh.io", "192.168.0.1").
		AddPorts(80, 445).
		AddFlags("-A").
		Run()
}
