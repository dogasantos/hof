package hof 

import (
	"fmt"
	"os"
	"bufio"
	"io/ioutil"
	"strings"
	"sync"
)

type Options struct {
	Domainf           string
	Hosts             string
	OutputFile        string
	SoaKbFile	      string
	Silent            bool
	Verbose           bool
}

func Process(options *Options) {	
	
	var found []string
	var hostname string 
	var knownDomain string
	var remaining []string

	bytesRead, _ := ioutil.ReadFile(options.Hosts)
	file_content := string(bytesRead)
	h := strings.Split(file_content, "\n")
	hosts := sliceUniqueElements(h)
	
	bR, _ := ioutil.ReadFile(options.Domainf)
	fc := string(bR)
	k := strings.Split(fc, "\n")
	knownDomains := sliceUniqueElements(k)
	
	if options.Verbose {
		fmt.Printf("[*] Known domains loaded: %d\n",len(knownDomains))
		fmt.Printf("[*] Target hosts loaded: %d\n",len(hosts))
	}
	
	fmt.Println("[*] Direct sub match")
	for _, knownDomain = range knownDomains {
		for _, hostname = range hosts {
			if sliceContainsElement(found, hostname) == false {
				if subVerify(knownDomain, hostname) ==  true {
					if options.Verbose {
						fmt.Printf("  + %s:SUB\n",hostname)
					}
					found = append(found, hostname)
					continue
				}
			}
		}
	}
	
	remaining = sliceDifference(found,hosts)
	if len(hosts) > len(found) { // we still have some hosts to check...
		fmt.Printf("[*] Remaining hosts: \n",len(remaining))
		fmt.Printf("[*] Building SOA data for %d known domains\n",len(knownDomains))

		soablacklist := loadSoaKb(options.SoaKbFile)
		
		knownSoaServers := buildKnownHostsSoaDb(options.Verbose,soablacklist,knownDomains)
		wg := new(sync.WaitGroup)
		var total []string
		var sbuffer []string
		var diff = remaining
		for _, hostname = range remaining {
			if sliceContainsElement(found, hostname) == false {
				sbuffer = append(sbuffer, hostname)
				if len(sbuffer) == 10 {
					if options.Verbose {
						fmt.Printf("  + Checking %d hosts batch\n",len(sbuffer))
					}
					channel := make(chan string)
					wg.Add(1)
					go asyncSoaVerify(wg, channel, options.Verbose, knownSoaServers, soablacklist, sbuffer)
					for msg := range channel {
						found = append(found, msg)
					}
					for _,a := range sbuffer{ 
						total = append(total, a)
						}
					sbuffer = nil
				}
				diff = sliceDifference(total, remaining)
				if len(diff) < 10 && len(diff) > 0 {
					if options.Verbose {
						fmt.Printf("  + Checking %d hosts batch\n",len(diff))
					}
					channel := make(chan string)
					wg.Add(1)
						
					go asyncSoaVerify(wg, channel, options.Verbose, knownSoaServers, soablacklist, sbuffer)

					for msg := range channel {
						found = append(found, msg)
					}
					for _,a := range diff { 
						total = append(total, a)
					}
					break
				}

			}
		}
		if options.Verbose {
			fmt.Printf("  + Total hosts verified: %d\n",len(total))
			fmt.Printf("  + Total hosts found: %d\n",len(found))
		}
		wg.Wait()
	}
	
	remaining = sliceDifference(found,hosts)
	if len(hosts) > len(found) { // we still have some hosts to check...
		fmt.Printf("[*] Remaining hosts: \n",len(remaining))
		fmt.Printf("[*] Building Whois tokens for %d known domains\n",len(knownDomains))

		knownWhoisData := buildKnownWhoisDb(options.Verbose,knownDomains)
		for _, h := range hosts {
			if sliceContainsElement(found, h) == false {
				if whoisVerify(knownWhoisData, h) ==  true {
					if options.Verbose {
						fmt.Printf("  + %s:WHOIS\n", h)
					}
					found = append(found, h)
					continue
				}
			}
		}
	}

	fmt.Printf("[*] Found %d hosts\n",len(found))

	
	
	if len(options.OutputFile) >0 {
		file, _ := os.Create(options.OutputFile)
		writer := bufio.NewWriter(file)
		for _, fh := range found {
			_, _ = writer.WriteString(fh + "\n")
		}
		writer.Flush()
	}
	for _, fh := range found {
		fmt.Println(fh)
	}

}