package hof 

import (
	"fmt"
	"github.com/projectdiscovery/retryabledns"
	"github.com/miekg/dns"
	"io/ioutil"
	"encoding/json"
	"strings"
	"log"
	"sync"
)
var DefaultResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"8.8.4.4:53", // Google
	"9.9.9.9:53", // Quad9
}

type soaKb struct {
	Soa 		[]string	`json:"soa"` 
	Domains 	[]string	`json:"domains"`
}


func loadSoaKb(file string) (content soaKb) {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalln(err)
	}

	err = json.Unmarshal(raw, &content)
	if err != nil {
		log.Fatalln(err)
	}
	return 
}

func dnsGetSoaServers(hostname string, blacklistedsoa soaKb) []string {
	
	var soa []string
	retries := 2
	dnsClient := retryabledns.New(DefaultResolvers, retries)
	dnsResponse, _ := dnsClient.Query(hostname, dns.TypeSOA)
	s := strings.Split(dnsResponse.Raw,"SOA")
	if len(s) == 3 {
		s1 := s[2]
		s2 := strings.ReplaceAll(s1, "\t", "")    
		s3 := strings.ReplaceAll(s2, "\n", "")
		s4 := strings.ReplaceAll(s3, ". ", ":")
		s5 := strings.Split(s4, ":")
		for _,t := range s5 {
			if strings.Contains(t,".") {
				dtok := ParseDomainTokens(t)					
				if sliceContainsElement(blacklistedsoa.Domains, dtok.Domain) == false {
					if sliceContainsElement(blacklistedsoa.Soa, t) == false {
						soa = append(soa,t)
					}
				}
			}
		}
	}
	return soa
}
func asyncDnsGetSoaServers(wg *sync.WaitGroup, msg chan string, verbose bool, buffer []string, blacklistedsoa soaKb) {
	defer wg.Done()
	var nbuffer []string

	for _,hostname := range buffer {
		dnsClient := retryabledns.New(DefaultResolvers, 2)
		dnsResponse, _ := dnsClient.Query(hostname, dns.TypeSOA)
		s := strings.Split(dnsResponse.Raw,"SOA")
		if len(s) == 3 {
			s1 := s[2]									// just
			s2 := strings.ReplaceAll(s1, "\t", "")    	// parsing
			s3 := strings.ReplaceAll(s2, "\n", "")		// the soa
			s4 := strings.ReplaceAll(s3, ". ", ":")		// response
			s5 := strings.Split(s4, ":")				// here
			for _,t := range s5 {						// we have 2 soa hosts on s5
				if strings.Contains(t,".") {			// seems to be a valid fqdn
					dtok := ParseDomainTokens(t)					
					if sliceContainsElement(blacklistedsoa.Domains, dtok.Domain) == false {	// the soa domain is not among blacklisted domains, which is good
						if sliceContainsElement(blacklistedsoa.Soa, t) == false {			// the soa fqdn host (t) is not blacklisted at all
							nbuffer = append(nbuffer, t)
							if verbose {
								fmt.Printf("  + Found SOA server for %s: %s\n",hostname,t)
							}
						}
					}
				}
			}
		}
	}
	for _,asoa := range nbuffer {
		msg <- asoa
	}
	close(msg)
}


func buildKnownHostsSoaDb(verbose bool, blacklistedsoa soaKb, knownDomainsList []string) []string {
	var buffer []string
	var total []string
	var diff = knownDomainsList
	var soaServersFound []string
	wg := new(sync.WaitGroup)


	fmt.Println("[*] Collecting SOA hosts")
	
	for _, knownDomain := range knownDomainsList {
		buffer = append(buffer, knownDomain)
		
		if len(buffer) == 10 {
			if verbose {
				fmt.Printf("  + Building kb for %d hosts\n",len(buffer))
			}
			channel := make(chan string)
			wg.Add(1)

			go asyncDnsGetSoaServers(wg, channel, verbose, buffer, blacklistedsoa)
			for msg := range channel {		// there is not mutch sense on handle the messages right after the routine start
				soaServersFound = append(soaServersFound,msg)	// as this is a blocking thing
			}													// but i'm learning... give me that

			for _,a := range buffer{ 
				total = append(total, a)
			}
			buffer = nil
		}

		diff = sliceDifference(total, knownDomainsList)

		if len(diff) < 10 && len(diff) > 0{
			if verbose {
				fmt.Printf("  + Building kb for %d hosts\n",len(diff))
			}
			channel := make(chan string)
			wg.Add(1)
			
			go asyncDnsGetSoaServers(wg, channel, verbose, diff, blacklistedsoa)

			for msg := range channel {
				soaServersFound = append(soaServersFound,msg)
			}
			for _,a := range diff { 
				total = append(total, a)
			}
			break
		}

	}
	if verbose {
		fmt.Printf("  + Total SOA servers in this kb: %d\n",len(soaServersFound))
	}
	wg.Wait()
	return soaServersFound
}

func soaVerify(knownSoaHosts []string, blacklistedsoa soaKb, host string) bool {
	retval := false
	targetSoa := dnsGetSoaServers(host, blacklistedsoa)

	for _, soa := range targetSoa {
		if sliceContainsElement(knownSoaHosts,soa) {
			retval = true
		}
	}
	return retval
}



func asyncSoaVerify(wg *sync.WaitGroup, msg chan string, verbose bool, knownSoaHosts []string, blacklistedsoa soaKb, buffer []string) {
	defer wg.Done()
	var nbuffer []string
	
	for _,hostname := range buffer {
		targetSoa := dnsGetSoaServers(hostname, blacklistedsoa)
		for _, soa := range targetSoa {
			if sliceContainsElement(knownSoaHosts,soa) {
				nbuffer = append(nbuffer,hostname)
				if verbose {
					fmt.Printf("  + %s:SOA\n",hostname)
				}
				break
			}
		}
	}

	for _,hf := range nbuffer {
		msg <- hf
	}
	close(msg)
}