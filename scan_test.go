package nmap

import "time"

func ExampleRunScan() {
	hosts := []string{"maxh.io", "192.168.0.1"}
	ports := []int{80, 445}
	opts := []string{"-F"}
	scan, _ := RunScan(hosts, ports, opts)
}

func ExampleRescan() {
	hosts := []string{"maxh.io", "192.168.0.1"}
	ports := []int{80, 445}
	opts := []string{"-F"}
	scan, _ := RunScan(hosts, ports, opts)
	time.Sleep(400 * time.Second)
	// The rescan will NOT use the "-F" flag as previously specified
	newScan, _ := scan.Rescan()
}
