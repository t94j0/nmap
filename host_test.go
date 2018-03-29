package nmap

import (
	"fmt"
	"testing"
	"time"
)

func portListToPortString(a []Port) (pl string) {
	for i, port := range a {
		if i == len(a)-1 {
			pl += fmt.Sprintf("%d", port.ID)
		} else {
			pl += fmt.Sprintf("%d, ", port.ID)
		}
	}
	return
}

func ExampleHost_Diff() {
	// Scan maxh.io one
	scan, _ := Init().AddHosts("maxh.io").Run()
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

func TestHost_Diff_hostempty(t *testing.T) {
	err := "Failed to find 8080 in additions"

	host := Host{Ports: []Port{}}
	altHost := Host{Ports: []Port{Port{ID: 8080, State: "open"}}}

	additions, removals := host.Diff(altHost)
	if len(removals) != 0 {
		t.Errorf("Removals is not exmpty")
	}
	if len(additions) != 1 {
		t.Errorf(err)
		return
	}
	if additions[0].ID != 8080 {
		t.Errorf(err)
	}
}

func TestHost_Diff_altempty(t *testing.T) {
	err := "Failed to find 8080 in removals"
	host := Host{Ports: []Port{Port{ID: 8080, State: "open"}}}
	altHost := Host{Ports: []Port{}}

	_, removals := host.Diff(altHost)
	if len(removals) != 1 {
		t.Errorf(err)
		return
	}
	if removals[0].ID != 8080 {
		t.Errorf(err)
	}
}

func TestHost_Diff_middlehost(t *testing.T) {
	host := Host{Ports: []Port{Port{ID: 40, State: "open"}, Port{ID: 80, State: "open"}, Port{ID: 8080, State: "open"}}}
	altHost := Host{Ports: []Port{Port{ID: 80, State: "open"}}}

	additions, removals := host.Diff(altHost)
	if len(additions) != 0 {
		a := "'"
		for _, addition := range additions {
			a += fmt.Sprintf("%d ", addition.ID)
		}
		a += "'"
		t.Errorf("Additions %s found\n", a)
	}
	if len(removals) != 2 {
		t.Errorf("Incorrect amount of removals found\n")
		return
	}

	shouldRemove := []uint32{40, 8080}
	for _, sr := range shouldRemove {
		srInRemovals := false
		for _, port := range removals {
			if port.ID == sr {
				srInRemovals = true
			}
		}
		if !srInRemovals {
			t.Errorf("Port %d should be removed\n", sr)
		}
	}
}

func TestHost_Diff_middlealt(t *testing.T) {
	host := Host{Ports: []Port{Port{ID: 80, State: "open"}}}
	altHost := Host{Ports: []Port{Port{ID: 40, State: "open"}, Port{ID: 80, State: "open"}, Port{ID: 8080, State: "open"}}}

	additions, removals := host.Diff(altHost)
	if len(removals) != 0 {
		a := "'"
		for _, removed := range removals {
			a += fmt.Sprintf("%d ", removed.ID)
		}
		a += "'"
		t.Errorf("Removals %s found\n", a)
	}
	if len(additions) != 2 {
		t.Errorf("Incorrect amount of additions found\n")
		return
	}

	shouldAdd := []uint32{40, 8080}
	for _, sa := range shouldAdd {
		srInAdditions := false
		for _, port := range additions {
			if port.ID == sa {
				srInAdditions = true
			}
		}
		if !srInAdditions {
			t.Errorf("Port %d should be removed\n", sa)
		}
	}
}

func TestHost_Diff_samethree(t *testing.T) {
	host := Host{Ports: []Port{Port{ID: 40, State: "open"}, Port{ID: 80, State: "open"}, Port{ID: 8080, State: "open"}}}
	altHost := Host{Ports: []Port{Port{ID: 40, State: "open"}, Port{ID: 80, State: "open"}, Port{ID: 8080, State: "open"}}}

	additions, removals := host.Diff(altHost)

	if len(additions) != 0 {
		t.Errorf("There should be no additions\n")
	}
	if len(removals) != 0 {
		t.Errorf("There should be no removals\n")
	}
}

func TestHost_Diff_state(t *testing.T) {
	host := Host{Ports: []Port{Port{ID: 40, State: "closed"}, Port{ID: 80, State: "closed"}, Port{ID: 8080, State: "closed"}}}
	altHost := Host{Ports: []Port{Port{ID: 40, State: "open"}, Port{ID: 80, State: "open"}, Port{ID: 8080, State: "open"}}}

	additions, removals := host.Diff(altHost)
	if len(additions) != 3 {
		added := portListToPortString(additions)
		t.Errorf("Additions '%s' found\n", added)
	}
	if len(removals) != 0 {
		removed := portListToPortString(removals)
		t.Errorf("Removals '%s' found\n", removed)
		t.Errorf("additions: %v\nremovals: %v\n", additions, removals)
	}
}
