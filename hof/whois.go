package hof 

import (
	"fmt"
	"strings"
	whoisparser "github.com/likexian/whois-parser-go"
	"github.com/likexian/whois-go"
	
)
func getParsedWhois(domain string) (result whoisparser.WhoisInfo, err error) {
	whoisRawData, err := whois.Whois(domain)
	if err != nil {
		return
	}
	result, err = whoisparser.Parse(whoisRawData)
	return
}


func buildKnownWhoisDb(verbose bool, knownDomainsList []string) []string {
	var tokens []string

	fmt.Println("[*] Collecting Whois data")
	for _,knownDomain := range knownDomainsList {
		if verbose {
			fmt.Printf("  + Known seed domain: %s\n",knownDomain)
		}
		whoisParsedData,_ := getParsedWhois(knownDomain)

		if whoisParsedData.Registrant != nil {
			if len(whoisParsedData.Registrant.Organization) > 1 {
				tokens = append(tokens, whoisParsedData.Registrant.Organization)
			}
			if len(whoisParsedData.Registrant.Email) > 1 {
				tokens = append(tokens, whoisParsedData.Registrant.Email)
			}
		}
		if whoisParsedData.Administrative != nil {
			if len(whoisParsedData.Administrative.Organization) > 1 {
				tokens = append(tokens, whoisParsedData.Administrative.Organization)
			}
			if len(whoisParsedData.Administrative.Email) > 1 {
				tokens = append(tokens, whoisParsedData.Administrative.Email)
			}
		}
		if whoisParsedData.Technical != nil {
			if len(whoisParsedData.Technical.Organization) > 1 {
				tokens = append(tokens, whoisParsedData.Technical.Organization)
			}
			if len(whoisParsedData.Technical.Email) > 1 {
				tokens = append(tokens, whoisParsedData.Technical.Email)
			}
		}
	}
	uniqueTokens := sliceUniqueElements(tokens)
	fmt.Println("  + Done")
	return uniqueTokens
}

func whoisCheck(pattern string, domain string) bool {
	var retval = false

	pWhois, err := getParsedWhois(domain)
	if err == nil {
		if pWhois.Registrant != nil {
			if strings.Contains(pWhois.Registrant.Organization,pattern) && retval == false {
				retval = true
			} else if strings.Contains(pWhois.Registrant.Email,pattern) && retval == false {
				retval = true
			}
		}
		if pWhois.Technical != nil && retval == false  {
			if strings.Contains(pWhois.Technical.Organization,pattern) && retval == false {
				retval = true
			} else if strings.Contains(pWhois.Technical.Email,pattern) && retval == false {
				retval = true
			}
		}

		if pWhois.Administrative != nil && retval == false {
			if strings.Contains(pWhois.Administrative.Organization,pattern) && retval == false {
				retval = true
			}
			if strings.Contains(pWhois.Administrative.Email,pattern) && retval == false {
				retval = true
			}
		}
	}

	return retval
}

func whoisVerify(knownTokens []string, host string) bool {
	var retval = false

	for _,token := range knownTokens {
		if whoisCheck(token, host) == true{
			retval = true
			break
		}
	}
	return retval
}
