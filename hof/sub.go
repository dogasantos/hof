package hof 

func subVerify(knownDomain string, host string) bool {
	var retval = false 
	dt := ParseDomainTokens(host)
	kdt := ParseDomainTokens(knownDomain)
	if dt.Domain == kdt.Domain {
		retval = true
	} 
	return retval
}
