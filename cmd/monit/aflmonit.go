package main

import (
	"github.com/alecthomas/kingpin"
	"github.com/jubnzv/aflmonit/monit"
)

const (
	version = "1.0.0"
)

var (
	debug    = kingpin.Flag("debug", "Enable additional output").Bool()
	path     = kingpin.Flag("path", "Path to AFL directory").Default(".").String()
	hostname = kingpin.Flag("hostname", "Server hostname").Default("0.0.0.0").String()
	port     = kingpin.Flag("port", "Server port").Uint16()
)

func main() {
	kingpin.Version(version)
	kingpin.Parse()
	if *port == 0 {
		*port = 7788
	}
	monit.StartServer(*path, *hostname, *port, *debug)
}
