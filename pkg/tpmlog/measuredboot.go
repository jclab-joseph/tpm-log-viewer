package tpmlog

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// DefaultDir 은 Windows 가 부팅마다 WBCL(TCG 이벤트 로그)을 남기는 위치다.
const DefaultDir = `C:\Windows\Logs\MeasuredBoot`

// 파일 이름은 "<부팅 카운터>-<재개 카운터>.log" 형식이다.
var logNameRE = regexp.MustCompile(`^(\d+)-(\d+)\.log$`)

// LogFile 은 MeasuredBoot 디렉터리의 로그 파일 하나를 가리킨다.
type LogFile struct {
	Path        string
	Name        string
	BootCount   uint64
	ResumeCount uint64
	Size        int64
	ModTime     time.Time
}

// String 은 "0000000028-0000000000.log (boot #28, resume 0)" 형태다.
func (f LogFile) String() string {
	return fmt.Sprintf("%s (boot #%d, resume %d, %d bytes, %s)",
		f.Name, f.BootCount, f.ResumeCount, f.Size, f.ModTime.Format("2006-01-02 15:04:05"))
}

// ListLogFiles 는 디렉터리의 로그 파일을 부팅/재개 카운터 오름차순으로 반환한다.
func ListLogFiles(dir string) ([]LogFile, error) {
	if dir == "" {
		dir = DefaultDir
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w%s", dir, err, permissionHint(err))
	}

	var out []LogFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := logNameRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		boot, err1 := strconv.ParseUint(m[1], 10, 64)
		resume, err2 := strconv.ParseUint(m[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		f := LogFile{
			Path:        filepath.Join(dir, e.Name()),
			Name:        e.Name(),
			BootCount:   boot,
			ResumeCount: resume,
		}
		if info, err := e.Info(); err == nil {
			f.Size = info.Size()
			f.ModTime = info.ModTime()
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no measured boot logs found in %s", dir)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].BootCount != out[j].BootCount {
			return out[i].BootCount < out[j].BootCount
		}
		return out[i].ResumeCount < out[j].ResumeCount
	})
	return out, nil
}

// LatestLogFile 은 마지막 부팅(가장 큰 부팅 카운터, 같으면 가장 큰 재개 카운터)의
// 로그 파일을 반환한다.
func LatestLogFile(dir string) (LogFile, error) {
	files, err := ListLogFiles(dir)
	if err != nil {
		return LogFile{}, err
	}
	return files[len(files)-1], nil
}

// LoadFile 은 지정한 로그 파일을 읽어 파싱한다.
func LoadFile(path string) (*Log, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w%s", path, err, permissionHint(err))
	}
	l, err := Parse(data)
	if l != nil {
		// 파싱이 중간에 끊겨도 읽은 부분은 돌려준다.
		return l, err
	}
	return nil, fmt.Errorf("parse %s: %w", path, err)
}

// LoadLatest 는 마지막 부팅의 로그를 찾아 읽고 파싱한다.
func LoadLatest(dir string) (*Log, LogFile, error) {
	f, err := LatestLogFile(dir)
	if err != nil {
		return nil, LogFile{}, err
	}
	l, err := LoadFile(f.Path)
	return l, f, err
}

// permissionHint 는 권한 오류일 때 관리자 권한 안내를 덧붙인다.
// MeasuredBoot 디렉터리는 목록 조회는 되지만 파일 읽기는 관리자 권한이 필요하다.
func permissionHint(err error) string {
	if os.IsPermission(err) {
		return " (hint: run as Administrator — files under " + DefaultDir + " are not readable by standard users)"
	}
	return ""
}
