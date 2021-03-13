package monit

import "time"

// FileInfo contains an information about the file from the `crashes` or `hangs` directory.
type FileInfo struct {
	Filename string    `json:"filename"`
	MTime    time.Time `json:"mtime"`
	ID       int       `json:"id"`
	Sig      int       `json:"sig"`
	Src      int       `json:"src"`
	Time     int       `json:"time"`
	Op       string    `json:"op"`
	Pos      int       `json:"pos"`
	Val      string    `json:"val"`
}
