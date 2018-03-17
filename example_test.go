package nmap

import (
	"fmt"
	"time"

	"github.com/t94j0/nmap"
)

func ExampleGetHost() {
	// All online hosts are added to the `scan` object
	scan, _ := nmap.Init().AddHosts("192.168.0.1/24").Run()
	// GetHost allows you to select one host from the list
	targetHost, _ := scan.GetHost("192.168.0.4")
	// It also searches hostnames
	targetHost, _ = scan.GetHost("maxh.io")
}

func ExampleDiff() {
	// Scan maxh.io one
	scan, _ := nmap.Init().AddHosts("maxh.io").Run()
	firstHost, _ := scan.GetHost("maxh.io")

	// Wait 100 seconds
	time.Sleep(100 * time.Second)

	// Rescan maxh.io
	scan, _ = scan.Run()
	secondHost, _ := scan.GetHost("maxh.io")

	// Get list of added and removed ports
	added, removed := firstHost.Diff(secondHost)
	fmt.Println(added, removed)
}

func ExampleRun() {
	scan, _ := nmap.Init().
		AddHosts("maxh.io", "192.168.0.1").
		AddPorts(80, 445).
		AddFlags("-A").
		Run()
}
