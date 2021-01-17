package hof 

import (
	"github.com/bobesa/go-domain-util/domainutil"
)


type DomainTokens struct {
	Subdomain string
	Domain string
	Tld string
}

func ParseDomainTokens(value string) (*DomainTokens){
	var d DomainTokens
	d.Subdomain = domainutil.Subdomain(value)
	d.Domain = domainutil.Domain(value)
	d.Tld = domainutil.DomainSuffix(value)

	return &d
}

func sliceContainsElement(slice []string, element string) bool {
	retval := false
	for _, e := range slice {
		if e == element {
			retval = true
		}
	}
	return retval
}



func sliceUniqueElements(slice []string) []string {
    keys := make(map[string]bool)
    list := []string{}
    for _, entry := range slice {
        if _, value := keys[entry]; !value {
            keys[entry] = true
            if len(entry) > 2 {
                list = append(list, entry)
            }
        }
    }
    return list
}


