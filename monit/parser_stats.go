package monit

import (
	"fmt"
	"strconv"
	"strings"
)

type AflStats struct {
	StartTime       uint64  `json:"start_time"`
	LastUpdate      uint64  `json:"last_update"`
	RunTime         uint64  `json:"run_time"`
	FuzzerPid       uint64  `json:"fuzzer_pid"`
	CyclesDone      uint64  `json:"cycles_done"`
	CyclesWoFinds   uint64  `json:"cycles_wo_finds"`
	ExecsDone       uint64  `json:"execs_done"`
	ExecsPerSec     float64 `json:"execs_per_sec"`
	ExecsPsLastMin  float64 `json:"execs_ps_last_min"`
	PathsTotal      uint64  `json:"paths_total"`
	PathsFavored    uint64  `json:"paths_favored"`
	PathsFound      uint64  `json:"paths_found"`
	PathsImported   uint64  `json:"paths_imported"`
	MaxDepth        uint64  `json:"max_depth"`
	CurPath         uint64  `json:"cur_path"`
	PendingFavs     uint64  `json:"pending_favs"`
	PendingTotal    uint64  `json:"pending_total"`
	VariablePaths   uint64  `json:"variable_paths"`
	Stability       float64 `json:"stability"`
	BitmapCvg       float64 `json:"bitmap_cvg"`
	UniqueCrashes   uint64  `json:"unique_crashes"`
	UniqueHangs     uint64  `json:"unique_hangs"`
	LastPath        uint64  `json:"last_path"`
	LastCrash       uint64  `json:"last_crash"`
	LastHang        uint64  `json:"last_hang"`
	ExecsSinceCrash uint64  `json:"execs_since_crash"`
	ExecTimeout     uint64  `json:"exec_timeout"`
	SlowestExecMs   uint64  `json:"slowest_exec_ms"`
	PeakRssMb       uint64  `json:"peak_rss_mb"`
	CPUAffinity     uint64  `json:"cpu_affinity"`
	EdgesFound      uint64  `json:"edges_found"`
	VarByteCount    uint64  `json:"var_byte_count"`
	HavocExpansion  uint64  `json:"havoc_expansion"`
	AflBanner       string  `json:"afl_banner"`
	AflVersion      string  `json:"afl_version"`
	TargetMode      string  `json:"target_mode"`
	CommandLine     string  `json:"command_line"`
}

// ParseStats parses an AFL fuzzer_stats file.
func ParseStats(data string) (*AflStats, error) {
	var fieldsCovered uint = 0

	var startTime uint64
	var lastUpdate uint64
	var runTime uint64
	var fuzzerPid uint64
	var cyclesDone uint64
	var cyclesWoFinds uint64
	var execsDone uint64
	var execsPerSec float64
	var execsPsLastMin float64
	var pathsTotal uint64
	var pathsFavored uint64
	var pathsFound uint64
	var pathsImported uint64
	var maxDepth uint64
	var curPath uint64
	var pendingFavs uint64
	var pendingTotal uint64
	var variablePaths uint64
	var stability float64
	var bitmapCvg float64
	var uniqueCrashes uint64
	var uniqueHangs uint64
	var lastPath uint64
	var lastCrash uint64
	var lastHang uint64
	var execsSinceCrash uint64
	var execTimeout uint64
	var slowestExecMs uint64
	var peakRssMb uint64
	var cpuAffinity uint64
	var edgesFound uint64
	var varByteCount uint64
	var havocExpansion uint64
	var aflBanner string
	var aflVersion string
	var targetMode string
	var commandLine string

	var err error

	for _, line := range strings.Split(data, "\n") {
		if line == "" {
			continue
		}
		values := strings.SplitN(line, ":", 2)
		key, value := values[0], values[1]
		key = strings.Trim(key, " ")
		value = strings.Trim(value, " ")

		switch key {
		case "start_time":
			startTime, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 0
		case "last_update":
			lastUpdate, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 1
		case "run_time":
			runTime, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 2
		case "fuzzer_pid":
			fuzzerPid, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 3
		case "cycles_done":
			cyclesDone, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 4
		case "cycles_wo_finds":
			cyclesWoFinds, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 5
		case "execs_done":
			execsDone, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 6
		case "execs_per_sec":
			execsPerSec, err = strconv.ParseFloat(value, 64)
			fieldsCovered |= 1 << 7
		case "execs_ps_last_min":
			execsPsLastMin, err = strconv.ParseFloat(value, 64)
			fieldsCovered |= 1 << 8
		case "paths_total":
			pathsTotal, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 9
		case "paths_favored":
			pathsFavored, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 10
		case "paths_found":
			pathsFound, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 11
		case "paths_imported":
			pathsImported, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 12
		case "max_depth":
			maxDepth, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 13
		case "cur_path":
			curPath, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 14
		case "pending_favs":
			pendingFavs, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 15
		case "pending_total":
			pendingTotal, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 16
		case "variable_paths":
			variablePaths, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 17
		case "stability":
			value = strings.Trim(value, "%")
			stability, err = strconv.ParseFloat(value, 64)
			fieldsCovered |= 1 << 18
		case "bitmap_cvg":
			value = strings.Trim(value, "%")
			bitmapCvg, err = strconv.ParseFloat(value, 64)
			fieldsCovered |= 1 << 19
		case "unique_crashes":
			uniqueCrashes, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 20
		case "unique_hangs":
			uniqueHangs, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 21
		case "last_path":
			lastPath, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 22
		case "last_crash":
			lastCrash, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 23
		case "last_hang":
			lastHang, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 24
		case "execs_since_crash":
			execsSinceCrash, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 25
		case "exec_timeout":
			execTimeout, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 26
		case "slowest_exec_ms":
			slowestExecMs, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 27
		case "peak_rss_mb":
			peakRssMb, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 28
		case "cpu_affinity":
			cpuAffinity, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 29
		case "edges_found":
			edgesFound, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 30
		case "var_byte_count":
			varByteCount, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 31
		case "havoc_expansion":
			havocExpansion, err = strconv.ParseUint(value, 10, 64)
			fieldsCovered |= 1 << 32
		case "afl_banner":
			aflBanner = value
			fieldsCovered |= 1 << 33
		case "afl_version":
			aflVersion = value
			fieldsCovered |= 1 << 34
		case "target_mode":
			targetMode = value
			fieldsCovered |= 1 << 35
		case "command_line":
			commandLine = value
			fieldsCovered |= 1 << 36
			// default:
			//     return nil, fmt.Errorf("Unexpected key: %s", key)
		}

		if err != nil {
			return nil, fmt.Errorf("invalid value for %s: %s", key, value)
		}
	}

	// TODO: Actually have a lookup and tell the user which fields were
	// missing
	if fieldsCovered != 137438953471 {
		msg := []string{"missing fields in stats:"}
		if (fieldsCovered & (1 << 0)) == 0 {
			msg = append(msg, "start_time")
		}
		if (fieldsCovered & (1 << 1)) == 0 {
			msg = append(msg, "last_update")
		}
		if (fieldsCovered & (1 << 2)) == 0 {
			msg = append(msg, "run_time")
		}
		if (fieldsCovered & (1 << 3)) == 0 {
			msg = append(msg, "fuzzer_pid")
		}
		if (fieldsCovered & (1 << 4)) == 0 {
			msg = append(msg, "cycles_done")
		}
		if (fieldsCovered & (1 << 5)) == 0 {
			msg = append(msg, "cycles_wo_finds")
		}
		if (fieldsCovered & (1 << 6)) == 0 {
			msg = append(msg, "execs_done")
		}
		if (fieldsCovered & (1 << 7)) == 0 {
			msg = append(msg, "execs_per_sec")
		}
		if (fieldsCovered & (1 << 8)) == 0 {
			msg = append(msg, "execs_ps_last_min")
		}
		if (fieldsCovered & (1 << 9)) == 0 {
			msg = append(msg, "paths_total")
		}
		if (fieldsCovered & (1 << 10)) == 0 {
			msg = append(msg, "paths_favored")
		}
		if (fieldsCovered & (1 << 11)) == 0 {
			msg = append(msg, "paths_found")
		}
		if (fieldsCovered & (1 << 12)) == 0 {
			msg = append(msg, "paths_imported")
		}
		if (fieldsCovered & (1 << 13)) == 0 {
			msg = append(msg, "max_depth")
		}
		if (fieldsCovered & (1 << 14)) == 0 {
			msg = append(msg, "cur_path")
		}
		if (fieldsCovered & (1 << 15)) == 0 {
			msg = append(msg, "pending_favs")
		}
		if (fieldsCovered & (1 << 16)) == 0 {
			msg = append(msg, "pending_total")
		}
		if (fieldsCovered & (1 << 17)) == 0 {
			msg = append(msg, "variable_paths")
		}
		if (fieldsCovered & (1 << 18)) == 0 {
			msg = append(msg, "stability")
		}
		if (fieldsCovered & (1 << 19)) == 0 {
			msg = append(msg, "bitmap_cvg")
		}
		if (fieldsCovered & (1 << 20)) == 0 {
			msg = append(msg, "unique_crashes")
		}
		if (fieldsCovered & (1 << 21)) == 0 {
			msg = append(msg, "unique_hangs")
		}
		if (fieldsCovered & (1 << 22)) == 0 {
			msg = append(msg, "last_path")
		}
		if (fieldsCovered & (1 << 23)) == 0 {
			msg = append(msg, "last_crash")
		}
		if (fieldsCovered & (1 << 24)) == 0 {
			msg = append(msg, "last_hang")
		}
		if (fieldsCovered & (1 << 25)) == 0 {
			msg = append(msg, "execs_since_crash")
		}
		if (fieldsCovered & (1 << 26)) == 0 {
			msg = append(msg, "exec_timeout")
		}
		if (fieldsCovered & (1 << 27)) == 0 {
			msg = append(msg, "slowest_exec_ms")
		}
		if (fieldsCovered & (1 << 28)) == 0 {
			msg = append(msg, "peak_rss_mb")
		}
		if (fieldsCovered & (1 << 29)) == 0 {
			msg = append(msg, "cpu_affinity")
		}
		if (fieldsCovered & (1 << 30)) == 0 {
			msg = append(msg, "edges_found")
		}
		if (fieldsCovered & (1 << 31)) == 0 {
			msg = append(msg, "var_byte_count")
		}
		if (fieldsCovered & (1 << 32)) == 0 {
			msg = append(msg, "havoc_expansion")
		}
		if (fieldsCovered & (1 << 33)) == 0 {
			msg = append(msg, "afl_banner")
		}
		if (fieldsCovered & (1 << 34)) == 0 {
			msg = append(msg, "afl_version")
		}
		if (fieldsCovered & (1 << 35)) == 0 {
			msg = append(msg, "target_mode")
		}
		if (fieldsCovered & (1 << 36)) == 0 {
			msg = append(msg, "command_line")
		}
		return nil, fmt.Errorf(strings.Join(msg, " "))
	}

	return &AflStats{
		StartTime:       startTime,
		LastUpdate:      lastUpdate,
		RunTime:         runTime,
		FuzzerPid:       fuzzerPid,
		CyclesDone:      cyclesDone,
		CyclesWoFinds:   cyclesWoFinds,
		ExecsDone:       execsDone,
		ExecsPerSec:     execsPerSec,
		ExecsPsLastMin:  execsPsLastMin,
		PathsTotal:      pathsTotal,
		PathsFavored:    pathsFavored,
		PathsFound:      pathsFound,
		PathsImported:   pathsImported,
		MaxDepth:        maxDepth,
		CurPath:         curPath,
		PendingFavs:     pendingFavs,
		PendingTotal:    pendingTotal,
		VariablePaths:   variablePaths,
		Stability:       stability,
		BitmapCvg:       bitmapCvg,
		UniqueCrashes:   uniqueCrashes,
		UniqueHangs:     uniqueHangs,
		LastPath:        lastPath,
		LastCrash:       lastCrash,
		LastHang:        lastHang,
		ExecsSinceCrash: execsSinceCrash,
		ExecTimeout:     execTimeout,
		SlowestExecMs:   slowestExecMs,
		PeakRssMb:       peakRssMb,
		CPUAffinity:     cpuAffinity,
		EdgesFound:      edgesFound,
		VarByteCount:    varByteCount,
		HavocExpansion:  havocExpansion,
		AflBanner:       aflBanner,
		AflVersion:      aflVersion,
		TargetMode:      targetMode,
		CommandLine:     commandLine,
	}, nil
}
