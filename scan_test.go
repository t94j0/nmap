package nmap

import (
	"fmt"
)

func ExampleScan_GetHost() {
	// All online hosts are added to the `scan` object
	scan, _ := Init().AddPorts(80).AddHosts("example.com").Run()
	// GetHost allows you to select one host from the list
	targetHost, _ := scan.GetHost("93.184.216.34")
	fmt.Println(targetHost.ToString())
	// It also searches hostnames
	targetHost, _ = scan.GetHost("maxh.io")
	fmt.Println(targetHost.ToString())
}

func ExampleScan_Run() {
	scan, _ := Init().
		AddHosts("maxh.io", "192.168.0.1").
		AddPorts(80, 445).
		AddFlags("-A").
		Run()
	fmt.Println(scan.ToString())
}

func ExampleScan_Intense() {
	scan, _ := Init().AddHosts("localhost").Intense().Run()
	fmt.Println(scan.ToString())
}
