package main

import (
	"fmt"
	"flag"
	"os"
	"github.com/dogasantos/hof/hof"
)

const banner = `
 _               _                                            __ _ _ _
| |__   ___  ___| |_       _____      ___ __   ___ _ __      / _(_) | |_ ___ _ __
| '_ \ / _ \/ __| __|____ / _ \ \ /\ / / '_ \ / _ \ '__|____| |_| | | __/ _ \ '__|
| | | | (_) \__ \ ||_____| (_) \ V  V /| | | |  __/ | |_____|  _| | | ||  __/ |
|_| |_|\___/|___/\__|     \___/ \_/\_/ |_| |_|\___|_|       |_| |_|_|\__\___|_|
==================================================================================
`
const Version = `0.1`

func showBanner() {
	fmt.Printf("%s", banner)
	fmt.Printf("\t\t\t\t\t\t\t\tversion: %s\n\n",Version)
}

func main() {	
	gpath := os.Getenv("GOPATH")
	ProjectDir := "/src/githuib.com/dogasantos/hof/"
	soaKbFile := "soakb.json"
	defaultConfig := gpath + ProjectDir + soaKbFile
	
	options := hof.Options{}
	
	flag.StringVar(&options.Domainf, 		"K", "", "List of known domains to serve as a seed to compare")
	flag.StringVar(&options.Hosts, 			"L", "", "File input with list of subdomains")
	flag.StringVar(&options.OutputFile, 	"o", "", "File to write output to (optional)")
	flag.StringVar(&options.SoaKbFile, 		"s", defaultConfig, "Soa servers to filter out (a default one is provided if not set)")
	flag.BoolVar(&options.Verbose, 			"verbose", false, "Verbose output")

	flag.Parse()

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	hof.Process(&options)

}