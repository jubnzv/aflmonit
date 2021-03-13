package monit

import (
	"testing"
)

const statsGood = `start_time        : 1615035540
last_update       : 1615039117
run_time          : 3576
fuzzer_pid        : 747808
cycles_done       : 0
cycles_wo_finds   : 0
execs_done        : 35393
execs_per_sec     : 9.90
execs_ps_last_min : 12.89
paths_total       : 553
paths_favored     : 119
paths_found       : 189
paths_imported    : 0
max_depth         : 4
cur_path          : 1
pending_favs      : 119
pending_total     : 553
variable_paths    : 0
stability         : 100.00%
bitmap_cvg        : 14.31%
unique_crashes    : 0
unique_hangs      : 0
last_path         : 1615038941
last_crash        : 0
last_hang         : 0
execs_since_crash : 35393
exec_timeout      : 220
slowest_exec_ms   : 0
peak_rss_mb       : 0
cpu_affinity      : 0
edges_found       : 4473
var_byte_count    : 0
havoc_expansion   : 0
afl_banner        : a.out
afl_version       : ++2.68c
target_mode       : shmem_testcase default
command_line      : afl-fuzz -i fuzz/input/ -o fuzz/output ./a.out @@`

func TestParseStats(t *testing.T) {
	stats, err := ParseStats(statsGood)
	if err != nil {
		t.Fatalf("Errored on %s", err)
	}
	if stats.StartTime != 1615035540 {
		t.Fatalf("Invalid StartTime")
	}
	if stats.LastUpdate != 1615039117 {
		t.Fatalf("Invalid LastUpdate")
	}
	if stats.RunTime != 3576 {
		t.Fatalf("Invalid RunTime")
	}
	if stats.FuzzerPid != 747808 {
		t.Fatalf("Invalid FuzzerPid")
	}
	if stats.CyclesDone != 0 {
		t.Fatalf("Invalid CyclesDone")
	}
	if stats.CyclesWoFinds != 0 {
		t.Fatalf("Invalid CyclesWoFinds")
	}
	if stats.ExecsDone != 35393 {
		t.Fatalf("Invalid ExecsDone")
	}
	if stats.ExecsPerSec != 9.90 {
		t.Fatalf("Invalid ExecsPerSec")
	}
	if stats.ExecsPsLastMin != 12.89 {
		t.Fatalf("Invalid ExecsPsLastMin")
	}
	if stats.PathsTotal != 553 {
		t.Fatalf("Invalid PathsTotal")
	}
	if stats.PathsFavored != 119 {
		t.Fatalf("Invalid PathsFavored")
	}
	if stats.PathsFound != 189 {
		t.Fatalf("Invalid PathsFound")
	}
	if stats.PathsImported != 0 {
		t.Fatalf("Invalid PathsImported")
	}
	if stats.MaxDepth != 4 {
		t.Fatalf("Invalid MaxDepth")
	}
	if stats.CurPath != 1 {
		t.Fatalf("Invalid CurPath")
	}
	if stats.PendingFavs != 119 {
		t.Fatalf("Invalid PendingFavs")
	}
	if stats.PendingTotal != 553 {
		t.Fatalf("Invalid PendingTotal")
	}
	if stats.VariablePaths != 0 {
		t.Fatalf("Invalid VariablePaths")
	}
	if stats.Stability != 100.00 {
		t.Fatalf("Invalid Stability")
	}
	if stats.BitmapCvg != 14.31 {
		t.Fatalf("Invalid BitmapCvg")
	}
	if stats.UniqueCrashes != 0 {
		t.Fatalf("Invalid UniqueCrashes")
	}
	if stats.UniqueHangs != 0 {
		t.Fatalf("Invalid UniqueHangs")
	}
	if stats.LastPath != 1615038941 {
		t.Fatalf("Invalid LastPath")
	}
	if stats.LastCrash != 0 {
		t.Fatalf("Invalid LastCrash")
	}
	if stats.LastHang != 0 {
		t.Fatalf("Invalid LastHang")
	}
	if stats.ExecsSinceCrash != 35393 {
		t.Fatalf("Invalid ExecsSinceCrash")
	}
	if stats.ExecTimeout != 220 {
		t.Fatalf("Invalid ExecTimeout")
	}
	if stats.SlowestExecMs != 0 {
		t.Fatalf("Invalid SlowestExecMs")
	}
	if stats.PeakRssMb != 0 {
		t.Fatalf("Invalid PeakRssMb")
	}
	if stats.CPUAffinity != 0 {
		t.Fatalf("Invalid CPUAffinity")
	}
	if stats.EdgesFound != 4473 {
		t.Fatalf("Invalid EdgesFound")
	}
	if stats.VarByteCount != 0 {
		t.Fatalf("Invalid VarByteCount")
	}
	if stats.HavocExpansion != 0 {
		t.Fatalf("Invalid HavocExpansion")
	}
	if stats.AflBanner != "a.out" {
		t.Fatalf("Invalid AflBanner")
	}
	if stats.AflVersion != "++2.68c" {
		t.Fatalf("Invalid AflVersion")
	}
	if stats.TargetMode != "shmem_testcase default" {
		t.Fatalf("Invalid TargetMode")
	}
	if stats.CommandLine != "afl-fuzz -i fuzz/input/ -o fuzz/output ./a.out @@" {
		t.Fatalf("Invalid CommandLine")
	}
}
