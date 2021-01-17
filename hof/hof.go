package hof 

import (
	"fmt"
	"os"
	"bufio"
	"io/ioutil"
	"strings"
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

	bytesRead, _ := ioutil.ReadFile(options.Hosts)
	file_content := string(bytesRead)
	hosts := strings.Split(file_content, "\n")
	
	bR, _ := ioutil.ReadFile(options.Domainf)
	fc := string(bR)
	k := strings.Split(fc, "\n")
	knownDomains := sliceUniqueElements(k)
	
	if options.Verbose {
		fmt.Printf("[*] Known domains loaded: %d\n",len(knownDomains))
		fmt.Printf("[*] Target hosts loaded: %d\n",len(hosts))
	}
	
	fmt.Println("[*] Comparing data")
	for _, knownDomain = range knownDomains {
		for _, hostname = range hosts {
			if len(hostname) > 2 {
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
	}

	if len(hosts) > len(found) { // we still have some hosts to check...
		fmt.Printf("[*] Building SOA data for the remaining hosts\n")
		soablacklist := loadSoaKb(options.SoaKbFile)
		
		knownSoaServers := buildKnownHostsSoaDb(options.Verbose,soablacklist,knownDomains)
		for _, knownDomain = range knownDomains {
			for _, hostname = range hosts {
				if len(hostname) > 2 {
					if sliceContainsElement(found, hostname) == false {
						
						if soaVerify(knownSoaServers, soablacklist,hostname) ==  true {
							if options.Verbose {
								fmt.Printf("  + %s:SOA\n",hostname)
							}
							found = append(found, hostname)
							continue
						}
					}
				}
			}
		}
	}


	if len(hosts) > len(found) { // we still have some hosts to check...
		fmt.Printf("[*] Building whois data for the remaining hosts\n")
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