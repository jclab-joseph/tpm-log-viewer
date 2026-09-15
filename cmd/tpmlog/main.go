// Command tpmlog 은 Windows Measured Boot(WBCL) TCG 이벤트 로그를 읽어 출력한다.
//
// 기본 동작은 C:\Windows\Logs\MeasuredBoot 에서 마지막 부팅의 로그를 찾아
// 모든 이벤트를 출력하는 것이다. 파싱은 pkg/tpmlog 에 있고 이 파일은 출력만 한다.
//
// 주의: C:\Windows\Logs\MeasuredBoot 의 파일은 관리자 권한으로만 읽을 수 있다.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"tpm-log/pkg/tpmlog"
)

type options struct {
	dir      string
	file     string
	list     bool
	pcrs     string
	evType   string
	alg      string
	hexDump  bool
	brief    bool
	noDigest bool
	replay   bool
	asJSON   bool
}

func main() {
	var o options
	flag.StringVar(&o.dir, "dir", tpmlog.DefaultDir, "measured boot log directory")
	flag.StringVar(&o.file, "file", "", "parse this log file instead of the last boot's log")
	flag.BoolVar(&o.list, "list", false, "list available log files and exit")
	flag.StringVar(&o.pcrs, "pcr", "", "only show these PCRs (comma separated, e.g. 4,7,11)")
	flag.StringVar(&o.evType, "type", "", "only show events whose type name contains this text (case-insensitive)")
	flag.StringVar(&o.alg, "alg", "", "only show digests of this algorithm (sha1, sha256, ...)")
	flag.BoolVar(&o.hexDump, "hex", false, "hex dump the full raw event data")
	flag.BoolVar(&o.brief, "brief", false, "one line per event (no detail lines)")
	flag.BoolVar(&o.noDigest, "no-digest", false, "do not print digests")
	flag.BoolVar(&o.replay, "replay", false, "also print PCR values recomputed from the log")
	flag.BoolVar(&o.asJSON, "json", false, "print as JSON")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: tpmlog [flags]\n\nPrints the TPM event log of the last boot from %s\n\nflags:\n", tpmlog.DefaultDir)
		flag.PrintDefaults()
	}
	flag.Parse()

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if o.list {
		return listFiles(o)
	}

	var (
		log  *tpmlog.Log
		file tpmlog.LogFile
		err  error
	)
	if o.file != "" {
		log, err = tpmlog.LoadFile(o.file)
		file = tpmlog.LogFile{Path: o.file, Name: o.file}
		if info, statErr := os.Stat(o.file); statErr == nil {
			file.Size = info.Size()
			file.ModTime = info.ModTime()
		}
	} else {
		log, file, err = tpmlog.LoadLatest(o.dir)
	}
	// 로그가 중간에 끊겨도(log != nil) 읽은 부분은 출력한다.
	if log == nil {
		return err
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}

	filter, err := newFilter(o)
	if err != nil {
		return err
	}

	if o.asJSON {
		return printJSON(log, file, filter, o)
	}
	printText(log, file, filter, o)
	return nil
}

func listFiles(o options) error {
	files, err := tpmlog.ListLogFiles(o.dir)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "BOOT\tRESUME\tSIZE\tMODIFIED\tFILE")
	for _, f := range files {
		fmt.Fprintf(w, "%d\t%d\t%d\t%s\t%s\n",
			f.BootCount, f.ResumeCount, f.Size, f.ModTime.Format("2006-01-02 15:04:05"), f.Path)
	}
	fmt.Fprintf(w, "\nlast boot: %s\n", files[len(files)-1].Path)
	return w.Flush()
}

// filter 는 출력 대상 이벤트/다이제스트를 고르는 조건이다.
type filter struct {
	pcrs     map[uint32]bool
	typeText string
	alg      string
}

func newFilter(o options) (filter, error) {
	f := filter{typeText: strings.ToLower(o.evType), alg: strings.ToLower(o.alg)}
	if o.pcrs != "" {
		f.pcrs = map[uint32]bool{}
		for _, part := range strings.Split(o.pcrs, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			n, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return f, fmt.Errorf("invalid -pcr value %q", part)
			}
			f.pcrs[uint32(n)] = true
		}
	}
	return f, nil
}

func (f filter) keepEvent(e *tpmlog.Event) bool {
	if f.pcrs != nil && !f.pcrs[e.PCRIndex] {
		return false
	}
	if f.typeText != "" && !strings.Contains(strings.ToLower(e.Type.String()), f.typeText) {
		return false
	}
	return true
}

func (f filter) keepDigest(d tpmlog.Digest) bool {
	return f.alg == "" || strings.EqualFold(d.Alg.String(), f.alg)
}

func printText(log *tpmlog.Log, file tpmlog.LogFile, f filter, o options) {
	printHeader(log, file)

	shown := 0
	for i := range log.Events {
		e := &log.Events[i]
		if !f.keepEvent(e) {
			continue
		}
		shown++
		printEvent(e, f, o)
	}

	fmt.Printf("\n%d event(s) printed", shown)
	if shown != len(log.Events) {
		fmt.Printf(" of %d", len(log.Events))
	}
	fmt.Println()

	if o.replay {
		printReplay(log)
	}
	if log.ParseError != nil {
		fmt.Printf("\nlog truncated or malformed: %v\n", log.ParseError)
	}
}

func printHeader(log *tpmlog.Log, file tpmlog.LogFile) {
	fmt.Println("TPM Measured Boot event log")
	fmt.Printf("  file    : %s\n", file.Path)
	if file.Size > 0 {
		fmt.Printf("  size    : %d bytes\n", file.Size)
	}
	if file.BootCount > 0 || file.ResumeCount > 0 {
		fmt.Printf("  boot    : #%d (resume %d)\n", file.BootCount, file.ResumeCount)
	}
	if !file.ModTime.IsZero() {
		fmt.Printf("  modified: %s\n", file.ModTime.Format("2006-01-02 15:04:05 -0700"))
	}
	fmt.Printf("  format  : %s\n", log.Format)
	if log.SpecID != nil {
		fmt.Printf("  spec    : %s\n", log.SpecID)
	}
	algs := log.Algorithms()
	names := make([]string, 0, len(algs))
	for _, a := range algs {
		names = append(names, a.String())
	}
	fmt.Printf("  digests : %s\n", strings.Join(names, " "))
	pcrs := log.PCRs()
	strs := make([]string, 0, len(pcrs))
	for _, p := range pcrs {
		strs = append(strs, strconv.FormatUint(uint64(p), 10))
	}
	fmt.Printf("  pcrs    : %s\n", strings.Join(strs, " "))
	fmt.Printf("  events  : %d\n", len(log.Events))
	if log.TrailingBytes > 0 {
		fmt.Printf("  padding : %d trailing bytes\n", log.TrailingBytes)
	}
	fmt.Println()
}

func printEvent(e *tpmlog.Event, f filter, o options) {
	data := e.Decoded()
	fmt.Printf("[%04d] PCR %02d  %s (0x%08X)  %d bytes\n",
		e.Sequence, e.PCRIndex, e.Type, uint32(e.Type), len(e.Data))

	if !o.noDigest {
		for _, d := range e.Digests {
			if f.keepDigest(d) {
				fmt.Printf("        %-8s %s\n", d.Alg, d.Hex())
			}
		}
	}
	fmt.Printf("        data     %s\n", data)

	if !o.brief {
		for _, line := range tpmlog.Details(data) {
			fmt.Printf("                 %s\n", line)
		}
	}
	if o.hexDump && len(e.Data) > 0 {
		for _, line := range hexLines(e.Data, 16) {
			fmt.Printf("        raw      %s\n", line)
		}
	}
}

// hexLines 는 바이트열을 "오프셋  hex  ascii" 형태의 줄로 나눈다.
func hexLines(b []byte, perLine int) []string {
	var out []string
	for off := 0; off < len(b); off += perLine {
		end := off + perLine
		if end > len(b) {
			end = len(b)
		}
		chunk := b[off:end]
		var ascii strings.Builder
		for _, c := range chunk {
			if c >= 0x20 && c <= 0x7E {
				ascii.WriteByte(c)
			} else {
				ascii.WriteByte('.')
			}
		}
		out = append(out, fmt.Sprintf("%04X  %-*s  %s",
			off, perLine*2+perLine-1, spacedHex(chunk), ascii.String()))
	}
	return out
}

func spacedHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = hex.EncodeToString([]byte{c})
	}
	return strings.Join(parts, " ")
}

func printReplay(log *tpmlog.Log) {
	for _, alg := range log.Algorithms() {
		values, err := log.ReplayPCRs(alg)
		if err != nil {
			fmt.Printf("\nPCR replay (%s): %v\n", alg, err)
			continue
		}
		if len(values) == 0 {
			// 예: crypto-agile 로그의 헤더 이벤트에만 SHA-1 다이제스트가 있는 경우.
			fmt.Printf("\nPCR replay (%s): no extendable %s digests in the log\n", alg, alg)
			continue
		}
		fmt.Printf("\nPCR values recomputed from the log (%s):\n", alg)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  PCR\tEXTENDS\tVALUE\tUSAGE")
		for _, v := range values {
			fmt.Fprintf(w, "  %02d\t%d\t%s\t%s\n",
				v.PCRIndex, v.Extends, hex.EncodeToString(v.Value), tpmlog.PCRDescription(v.PCRIndex))
		}
		w.Flush()
	}
}

// --- JSON 출력 ---

type jsonOutput struct {
	File    jsonFile     `json:"file"`
	Format  string       `json:"format"`
	SpecID  string       `json:"specId,omitempty"`
	Algs    []string     `json:"algorithms"`
	PCRs    []uint32     `json:"pcrs"`
	Total   int          `json:"totalEvents"`
	Trailer int          `json:"trailingBytes,omitempty"`
	Error   string       `json:"parseError,omitempty"`
	Events  []jsonEvent  `json:"events"`
	Replay  []jsonReplay `json:"replay,omitempty"`
}

type jsonFile struct {
	Path        string `json:"path"`
	BootCount   uint64 `json:"bootCount,omitempty"`
	ResumeCount uint64 `json:"resumeCount"`
	Size        int64  `json:"size,omitempty"`
	Modified    string `json:"modified,omitempty"`
}

type jsonEvent struct {
	Sequence int               `json:"sequence"`
	Offset   int               `json:"offset"`
	PCRIndex uint32            `json:"pcr"`
	Type     string            `json:"type"`
	TypeID   uint32            `json:"typeId"`
	Digests  map[string]string `json:"digests"`
	DataSize int               `json:"dataSize"`
	Summary  string            `json:"summary"`
	Details  []string          `json:"details,omitempty"`
	DataHex  string            `json:"dataHex,omitempty"`
}

type jsonReplay struct {
	Alg    string            `json:"algorithm"`
	Values map[string]string `json:"values"`
}

func printJSON(log *tpmlog.Log, file tpmlog.LogFile, f filter, o options) error {
	out := jsonOutput{
		File: jsonFile{
			Path:        file.Path,
			BootCount:   file.BootCount,
			ResumeCount: file.ResumeCount,
			Size:        file.Size,
		},
		Format:  log.Format.String(),
		PCRs:    log.PCRs(),
		Total:   len(log.Events),
		Trailer: log.TrailingBytes,
		Events:  []jsonEvent{},
	}
	if !file.ModTime.IsZero() {
		out.File.Modified = file.ModTime.Format("2006-01-02T15:04:05Z07:00")
	}
	if log.SpecID != nil {
		out.SpecID = log.SpecID.String()
	}
	for _, a := range log.Algorithms() {
		out.Algs = append(out.Algs, a.String())
	}
	if log.ParseError != nil {
		out.Error = log.ParseError.Error()
	}

	for i := range log.Events {
		e := &log.Events[i]
		if !f.keepEvent(e) {
			continue
		}
		data := e.Decoded()
		je := jsonEvent{
			Sequence: e.Sequence,
			Offset:   e.Offset,
			PCRIndex: e.PCRIndex,
			Type:     e.Type.String(),
			TypeID:   uint32(e.Type),
			Digests:  map[string]string{},
			DataSize: len(e.Data),
			Summary:  data.String(),
		}
		if !o.noDigest {
			for _, d := range e.Digests {
				if f.keepDigest(d) {
					je.Digests[d.Alg.String()] = d.Hex()
				}
			}
		}
		if !o.brief {
			je.Details = tpmlog.Details(data)
		}
		if o.hexDump {
			je.DataHex = hex.EncodeToString(e.Data)
		}
		out.Events = append(out.Events, je)
	}

	if o.replay {
		for _, alg := range log.Algorithms() {
			values, err := log.ReplayPCRs(alg)
			if err != nil {
				continue
			}
			r := jsonReplay{Alg: alg.String(), Values: map[string]string{}}
			for _, v := range values {
				r.Values[strconv.FormatUint(uint64(v.PCRIndex), 10)] = hex.EncodeToString(v.Value)
			}
			out.Replay = append(out.Replay, r)
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
