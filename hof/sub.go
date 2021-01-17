package hof 

func subVerify(knownDomain string, host string) bool {
	var retval = false 
	dt := ParseDomainTokens(host)
	if dt.Domain == knownDomain {
		retval = true
	} 
	return retval
}
