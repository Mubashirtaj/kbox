package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel bpf bpf/trace.c -- -I/usr/include -mcpu=v3

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const historySize = 10

const (
	syscallOpenat  = 1
	syscallConnect = 2
)

type syscallRecord struct {
	Syscall uint32
	Ret     int32
	Family  uint16
	Port    uint16
	Address [16]byte
	Path    [128]byte
}

type crashEvent struct {
	Pid          uint32
	Uid          uint32
	ExitStatus   int32
	HistoryCount uint32
	TimestampNs  uint64
	Comm         [16]byte
	History      [historySize]syscallRecord
}

type syscallReport struct {
	Syscall string `json:"syscall"`
	Result  int32  `json:"result"`
	Errno   int32  `json:"errno"`
	Path    string `json:"path,omitempty"`
	Address string `json:"address,omitempty"`
	Port    uint16 `json:"port,omitempty"`
}

type crashReport struct {
	Pid         uint32          `json:"pid"`
	Uid         uint32          `json:"uid"`
	Process     string          `json:"process"`
	ExitStatus  int32           `json:"exit_status"`
	ExitCode    uint8           `json:"exit_code"`
	Signal      uint8           `json:"signal"`
	Cgroup      string          `json:"cgroup,omitempty"`
	CrashName   string          `json:"crash_name"`
	OccurredAt  time.Time       `json:"occurred_at"`
	FailedCalls []syscallReport `json:"failed_calls"`
}

func main() {
	reportDirectory := os.Getenv("CRASH_REPORT_DIR")
	if reportDirectory == "" {
		reportDirectory = "crash-reports"
	}

	startedAt := time.Now()
	var monotonicStart unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonicStart); err != nil {
		log.Fatalf("Reading monotonic clock failed: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects failed: %v", err)
	}
	defer objs.Close()

	tracepoints := []struct {
		name string
		prog *ebpf.Program
	}{
		{name: "sys_enter_openat", prog: objs.TraceEnterOpenat},
		{name: "sys_exit_openat", prog: objs.TraceExitOpenat},
		{name: "sys_enter_connect", prog: objs.TraceEnterConnect},
		{name: "sys_exit_connect", prog: objs.TraceExitConnect},
		{name: "sched_process_exit", prog: objs.TraceProcessExit},
	}

	links := make([]link.Link, 0, len(tracepoints))
	for _, tp := range tracepoints {
		group := "syscalls"
		if tp.name == "sched_process_exit" {
			group = "sched"
		}
		attached, err := link.Tracepoint(group, tp.name, tp.prog, nil)
		if err != nil {
			log.Fatalf("Attaching tracepoint %s/%s failed: %v", group, tp.name, err)
		}
		links = append(links, attached)
	}
	defer func() {
		for _, attached := range links {
			if err := attached.Close(); err != nil {
				log.Printf("Closing tracepoint failed: %v", err)
			}
		}
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ringbuf reader failed: %v", err)
	}
	defer rd.Close()

	log.Println("Crash tracer attached; saving qualifying process crash reports to crash-reports/.")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Reading from ringbuf failed: %v", err)
				continue
			}

			if len(record.RawSample) != binary.Size(crashEvent{}) {
				log.Printf("Unexpected crash event size: got %d bytes, want %d", len(record.RawSample), binary.Size(crashEvent{}))
				continue
			}
			var event crashEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Parsing crash event failed: %v", err)
				continue
			}
			if !isFatalExit(event) {
				continue
			}

			cgroupPath := fmt.Sprintf("/proc/%d/cgroup", event.Pid)
			cgroup, cgroupErr := os.ReadFile(cgroupPath)
			if cgroupErr != nil {
				log.Printf("Cgroup metadata unavailable for PID %d: reading %s failed: %v", event.Pid, cgroupPath, cgroupErr)
			}

			occurredAt, err := eventTime(startedAt, uint64(monotonicStart.Nano()), event.TimestampNs)
			if err != nil {
				log.Printf("Skipping alert for PID %d: converting crash timestamp failed: %v", event.Pid, err)
				continue
			}
			report, err := makeCrashReport(event)
			if err != nil {
				log.Printf("Formatting crash event failed: %v", err)
				continue
			}
			if cgroupErr == nil {
				report.Cgroup = strings.TrimSpace(string(cgroup))
			}
			report.CrashName = crashName(report)
			report.OccurredAt = occurredAt
			path, err := saveCrashReport(reportDirectory, report)
			if err != nil {
				log.Printf("Saving crash report failed: %v", err)
				continue
			}
			log.Printf("Crash report saved: %s", path)
			if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
				log.Printf("Writing crash report failed: %v", err)
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutting down tracer...")
}

func makeCrashReport(event crashEvent) (crashReport, error) {
	if event.HistoryCount > historySize {
		return crashReport{}, fmt.Errorf("invalid history count %d", event.HistoryCount)
	}

	report := crashReport{
		Pid:         event.Pid,
		Uid:         event.Uid,
		Process:     cString(event.Comm[:]),
		ExitStatus:  event.ExitStatus,
		ExitCode:    uint8(event.ExitStatus >> 8),
		Signal:      uint8(event.ExitStatus & 0x7f),
		FailedCalls: make([]syscallReport, 0, event.HistoryCount),
	}

	for _, record := range event.History[:event.HistoryCount] {
		if record.Syscall == 0 {
			continue
		}
		call := syscallReport{
			Syscall: syscallName(record.Syscall),
			Result:  record.Ret,
		}
		if record.Ret < 0 {
			call.Errno = -record.Ret
		}
		switch record.Syscall {
		case syscallOpenat:
			call.Path = cString(record.Path[:])
		case syscallConnect:
			call.Address = connectAddress(record)
			call.Port = binary.BigEndian.Uint16([]byte{byte(record.Port), byte(record.Port >> 8)})
		default:
			return crashReport{}, fmt.Errorf("unknown syscall kind %d", record.Syscall)
		}
		report.FailedCalls = append(report.FailedCalls, call)
	}
	return report, nil
}

func crashName(report crashReport) string {
	if report.Signal == 0 {
		return fmt.Sprintf("exit-code-%d", report.ExitCode)
	}
	switch syscall.Signal(report.Signal) {
	case syscall.SIGSEGV:
		return "SIGSEGV"
	case syscall.SIGABRT:
		return "SIGABRT"
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGBUS:
		return "SIGBUS"
	case syscall.SIGILL:
		return "SIGILL"
	case syscall.SIGFPE:
		return "SIGFPE"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGQUIT:
		return "SIGQUIT"
	case syscall.SIGINT:
		return "SIGINT"
	default:
		return fmt.Sprintf("signal-%d", report.Signal)
	}
}

func eventTime(startedAt time.Time, monotonicStartNs, eventTimestampNs uint64) (time.Time, error) {
	if eventTimestampNs < monotonicStartNs {
		return time.Time{}, fmt.Errorf("event timestamp precedes tracer start")
	}
	delta := eventTimestampNs - monotonicStartNs
	if delta > uint64(1<<63-1) {
		return time.Time{}, fmt.Errorf("event timestamp delta overflows time.Duration")
	}
	return startedAt.Add(time.Duration(delta)).UTC(), nil
}

func saveCrashReport(directory string, report crashReport) (string, error) {
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("creating report directory: %w", err)
	}
	dirFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("opening report directory: %w", err)
	}
	defer unix.Close(dirFD)
	if err := setSudoOwner(dirFD); err != nil {
		return "", fmt.Errorf("setting report directory owner: %w", err)
	}
	if err := unix.Fchmod(dirFD, 0700); err != nil {
		return "", fmt.Errorf("setting report directory permissions: %w", err)
	}

	stamp := report.OccurredAt.UTC().Format("20060102T150405.000000000Z")
	filename := fmt.Sprintf("%s_%s_%s_pid%d.json",
		stamp,
		safeFilePart(report.Process),
		safeFilePart(report.CrashName),
		report.Pid,
	)
	path := filepath.Join(directory, filename)
	fileFD, err := unix.Openat(dirFD, filename, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return "", fmt.Errorf("creating report file: %w", err)
	}
	file := os.NewFile(uintptr(fileFD), path)

	if err := setSudoOwner(fileFD); err != nil {
		return "", discardReport(file, dirFD, filename, fmt.Errorf("setting report file owner: %w", err))
	}
	if err := unix.Fchmod(fileFD, 0600); err != nil {
		return "", discardReport(file, dirFD, filename, fmt.Errorf("setting report file permissions: %w", err))
	}
	if err := json.NewEncoder(file).Encode(report); err != nil {
		return "", discardReport(file, dirFD, filename, fmt.Errorf("encoding report: %w", err))
	}
	if err := file.Sync(); err != nil {
		return "", discardReport(file, dirFD, filename, fmt.Errorf("syncing report: %w", err))
	}
	if err := file.Close(); err != nil {
		removeErr := unix.Unlinkat(dirFD, filename, 0)
		return "", errors.Join(fmt.Errorf("closing report file: %w", err), removeErr)
	}
	return path, nil
}

func setSudoOwner(fd int) error {
	if os.Geteuid() != 0 {
		return nil
	}
	uidValue, hasUID := os.LookupEnv("CRASH_REPORT_UID")
	gidValue, hasGID := os.LookupEnv("CRASH_REPORT_GID")
	if !hasUID && !hasGID {
		uidValue, hasUID = os.LookupEnv("SUDO_UID")
		gidValue, hasGID = os.LookupEnv("SUDO_GID")
	}
	if !hasUID || !hasGID {
		if hasUID || hasGID {
			return fmt.Errorf("both report owner UID and GID must be set")
		}
		return nil
	}
	uid, err := strconv.Atoi(uidValue)
	if err != nil {
		return fmt.Errorf("invalid SUDO_UID %q: %w", uidValue, err)
	}
	gid, err := strconv.Atoi(gidValue)
	if err != nil {
		return fmt.Errorf("invalid SUDO_GID %q: %w", gidValue, err)
	}
	return unix.Fchown(fd, uid, gid)
}

func discardReport(file *os.File, dirFD int, filename string, cause error) error {
	closeErr := file.Close()
	removeErr := unix.Unlinkat(dirFD, filename, 0)
	return errors.Join(cause, closeErr, removeErr)
}

func safeFilePart(value string) string {
	var safe strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z',
			char >= '0' && char <= '9', char == '-', char == '_':
			safe.WriteRune(char)
		default:
			safe.WriteByte('_')
		}
	}
	if safe.Len() == 0 {
		return "unknown"
	}
	return safe.String()
}

func isFatalExit(event crashEvent) bool {
	status := uint32(event.ExitStatus)
	signal := status & 0x7f
	exitCode := (status >> 8) & 0xff
	return signal > 0 || exitCode > 1
}

func syscallName(kind uint32) string {
	switch kind {
	case syscallOpenat:
		return "openat"
	case syscallConnect:
		return "connect"
	default:
		return fmt.Sprintf("unknown(%d)", kind)
	}
}

func connectAddress(record syscallRecord) string {
	switch record.Family {
	case syscall.AF_INET:
		return netip.AddrFrom4([4]byte(record.Address[:4])).String()
	case syscall.AF_INET6:
		return netip.AddrFrom16(record.Address).String()
	default:
		return fmt.Sprintf("family:%d", record.Family)
	}
}

func cString(value []byte) string {
	if i := bytes.IndexByte(value, 0); i >= 0 {
		value = value[:i]
	}
	return string(value)
}
