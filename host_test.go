package nmap

import (
	"fmt"
	"time"

	"github.com/t94j0/nmap"
)

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
