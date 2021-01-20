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

func sliceDifference(slice1 []string, slice2 []string) []string {
    var diff []string

    for i := 0; i < 2; i++ {
        for _, s1 := range slice1 {
            found := false
            for _, s2 := range slice2 {
                if s1 == s2 {
                    found = true
                    break
                }
            }
            if !found {
                diff = append(diff, s1)
            }
        }
        if i == 0 {
            slice1, slice2 = slice2, slice1
        }
    }
    return diff
}

