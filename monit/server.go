package monit

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
)

//go:embed static
var embeddedFiles embed.FS

type aflServer struct {
	fileManager *AflFileManager
}

func NewServer(fm *AflFileManager) *aflServer {
	return &aflServer{fileManager: fm}
}

func (s *aflServer) fuzzerStatsHandler(w http.ResponseWriter, req *http.Request) {
	stats, err := s.fileManager.ReadStatsFile()
	if err != nil {
		log.Fatalln(err)
		if js, err := json.Marshal(err); err == nil {
			w.Write(js)
		}
		return
	}

	js, err := json.Marshal(*stats)
	if err != nil {
		log.Fatalln(err)
		if js, err := json.Marshal(err); err == nil {
			w.Write(js)
		}
		return
	}

	w.Write(js)
}

// crashesHandler handles the requests to list all the crashes.
func (s *aflServer) crashesHandler(w http.ResponseWriter, req *http.Request) {
	crashes, err := s.fileManager.GetCrashesList()
	if err != nil {
		log.Fatalln(err)
		if js, err := json.Marshal(err); err == nil {
			w.Write(js)
		}
		return
	}
	if js, err := json.Marshal(crashes); err == nil {
		w.Write(js)
	}
}

// hangsHandler handles the requests to list all the hangs.
func (s *aflServer) hangsHandler(w http.ResponseWriter, req *http.Request) {
	hangs, err := s.fileManager.GetHangsList()
	if err != nil {
		log.Fatalln(err)
		if js, err := json.Marshal(err); err == nil {
			w.Write(js)
		}
		return
	}
	if js, err := json.Marshal(hangs); err == nil {
		w.Write(js)
	}
}

func StartServer(aflPath string, address string, port uint16, debug bool) {
	log.Printf("Starting server on http://%s:%d/ (path=%s debug=%t)", address, port, aflPath, debug)

	fm, err := NewAflFileManager(aflPath)
	if err != nil {
		panic(err)
	}

	fsys, err := fs.Sub(embeddedFiles, "static")
	if err != nil {
		panic(err)
	}

	server := NewServer(fm)

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(fsys)))
	mux.Handle("/crashes/", http.StripPrefix("/crashes", http.FileServer(http.Dir(server.fileManager.CrashesPath()))))
	mux.Handle("/hangs/", http.StripPrefix("/hangs", http.FileServer(http.Dir(server.fileManager.HangsPath()))))
	mux.HandleFunc("/api/v1/fuzzer_stats", server.fuzzerStatsHandler)
	mux.HandleFunc("/api/v1/crashes", server.crashesHandler)
	mux.HandleFunc("/api/v1/hangs", server.hangsHandler)
	host := fmt.Sprintf("%s:%d", address, port)
	log.Fatal(http.ListenAndServe(host, mux))
}
