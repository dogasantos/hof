package hof 

import (
	"fmt"
	"github.com/projectdiscovery/retryabledns"
	"github.com/miekg/dns"
	"io/ioutil"
	"encoding/json"
	"strings"
	"log"
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

func buildKnownHostsSoaDb(verbose bool,blacklistedsoa soaKb, knownDomainsList []string) []string {
	var knownSoaHosts []string

	fmt.Println("[*] Collecting SOA hosts")
	for _, knownDomain := range knownDomainsList {
		if verbose {
			fmt.Printf("  + Known seed domain: %s\n",knownDomain)
		}
		soahosts := dnsGetSoaServers(knownDomain, blacklistedsoa)
		for _,soa := range soahosts {
			knownSoaHosts = append(knownSoaHosts, soa)
		}
	}
	uniqueSoaHosts := sliceUniqueElements(knownSoaHosts)
	return uniqueSoaHosts
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