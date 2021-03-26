package monit

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type AflFileManager struct {
	outputDir string // Output directory of AFL fuzzer
}

func NewAflFileManager(basedir string) (*AflFileManager, error) {
	fm := &AflFileManager{}
	fm.outputDir = basedir
	if err := fm.verifyPath(); err != nil {
		return nil, err
	}
	if _, err := fm.ReadStatsFile(); err != nil {
		return nil, err
	}
	return fm, nil
}

// verifyPath verifies that the path contains all the necessary files.
func (m AflFileManager) verifyPath() error {
	for _, filename := range []string{m.outputDir, m.StatsPath(), m.CrashesPath(), m.HangsPath()} {
		if _, err := os.OpenFile(filename, os.O_RDONLY, 0644); errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (m AflFileManager) StatsPath() string {
	return filepath.Join(m.outputDir, "fuzzer_stats")
}

func (m AflFileManager) CrashesPath() string {
	return filepath.Join(m.outputDir, "crashes")
}

func (m AflFileManager) HangsPath() string {
	return filepath.Join(m.outputDir, "hangs")
}

func (m AflFileManager) ReadStatsFile() (*AflStats, error) {
	buf, err := ioutil.ReadFile(m.StatsPath())
	if err != nil {
		return nil, err
	}
	return ParseStats(string(buf))
}

func getFileInfoFromFileName(filename string) (fi FileInfo, err error) {
	parts := strings.Split(filename, ",")
	if len(parts) < 5 {
		err = fmt.Errorf("unexpected file name: %s", filename)
		return
	}

	// id:
	if len(parts[0]) < 4 {
		err = fmt.Errorf("unexpected field: %s", parts[0])
		return
	}
	if fi.ID, err = strconv.Atoi(parts[0][3:]); err != nil {
		return
	}

	// sig:
	if len(parts[1]) < 5 {
		err = fmt.Errorf("unexpected field: %s", parts[1])
		return
	}
	if fi.Sig, err = strconv.Atoi(parts[1][4:]); err != nil {
		return
	}

	// src:
	if len(parts[2]) < 5 {
		err = fmt.Errorf("unexpected field: %s", parts[2])
		return
	}
	if fi.Src, err = strconv.Atoi(parts[2][4:]); err != nil {
		return
	}

	// time:
	if len(parts[3]) < 6 {
		err = fmt.Errorf("unexpected field: %s", parts[3])
		return
	}
	if fi.Time, err = strconv.Atoi(parts[3][5:]); err != nil {
		return
	}

	// op:
	if len(parts[4]) < 4 {
		err = fmt.Errorf("unexpected field: %s", parts[4])
		return
	}
	fi.Op = parts[4][3:]

	// pos:
	if len(parts[5]) < 5 {
		err = fmt.Errorf("unexpected field: %s", parts[5])
		return
	}
	if fi.Pos, err = strconv.Atoi(parts[5][4:]); err != nil {
		return
	}

	return
}

func (m AflFileManager) GetCrashesList() ([]FileInfo, error) {
	files, err := ioutil.ReadDir(m.CrashesPath())
	if err != nil {
		return nil, err
	}
	var result []FileInfo
	for _, file := range files {
		fi, err := getFileInfoFromFileName(file.Name())
		if err == nil {
			fi.Filename = file.Name()
			fi.MTime = file.ModTime()
			result = append(result, fi)
		}
	}
	return result, nil
}

func (m AflFileManager) GetHangsList() ([]FileInfo, error) {
	files, err := ioutil.ReadDir(m.HangsPath())
	if err != nil {
		return nil, err
	}
	var result []FileInfo
	for _, file := range files {
		fi, err := getFileInfoFromFileName(file.Name())
		if err == nil {
			fi.Filename = file.Name()
			fi.MTime = file.ModTime()
			result = append(result, fi)
		}
	}
	return result, nil
}
