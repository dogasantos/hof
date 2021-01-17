# host-owner-filter
This tool is designed to take a host or a list of hosts and a domain or a list of domains as input and it check the ownership of each host against the domain list.

In order to do that, this tool will execute 3 types of tests, and here are the details of each test:

### Direct Subdomain Match

Check if a given host or list of hosts are under the provided seed-domain or any of the provided seed-domain list.

### Whois Match

Check if the domain of a given host has the same Name, Organization or Email as the seed-domain or any of the provided seed-domain list. 
That comparision will be applied against the Registrant, Technical and Administrative whois groups.

NOTE: The ETA is directly impacted by the seed-domain list size.

### SOA match

Check if the SOA of a given host is the same as any domain in provided seed-domain list. 

NOTE: This might produce some false positives, so you must be careful to not add domains that the SOA is CloudFlare host, for instance.
It's a very common pattern for a company that has many domains, to use a standard dns to host many dns zones. This step is designed to catch this situation.



