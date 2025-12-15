package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMakeCrashReport(t *testing.T) {
	var event crashEvent
	event.Pid = 42
	event.Uid = 1000
	event.ExitStatus = int32(syscall.SIGSEGV)
	event.HistoryCount = 2
	copy(event.Comm[:], "worker")
	event.History[0] = syscallRecord{
		Syscall: syscallOpenat,
		Ret:     -int32(syscall.ENOENT),
	}
	copy(event.History[0].Path[:], "/missing")
	event.History[1] = syscallRecord{
		Syscall: syscallConnect,
		Ret:     -int32(syscall.ECONNREFUSED),
		Family:  syscall.AF_INET,
		Port:    0xbb01,
		Address: [16]byte{127, 0, 0, 1},
	}

	report, err := makeCrashReport(event)
	if err != nil {
		t.Fatalf("makeCrashReport() error = %v", err)
	}
	if report.Process != "worker" || report.ExitCode != 0 || report.Signal != uint8(syscall.SIGSEGV) {
		t.Fatalf("unexpected process/exit details: %+v", report)
	}
	if len(report.FailedCalls) != 2 {
		t.Fatalf("failed call count = %d, want 2", len(report.FailedCalls))
	}
	if call := report.FailedCalls[0]; call.Syscall != "openat" || call.Path != "/missing" || call.Errno != int32(syscall.ENOENT) {
		t.Errorf("unexpected openat report: %+v", call)
	}
	if call := report.FailedCalls[1]; call.Syscall != "connect" || call.Address != "127.0.0.1" || call.Port != 443 {
		t.Errorf("unexpected connect report: %+v", call)
	}
}

func TestMakeCrashReportRejectsInvalidHistoryCount(t *testing.T) {
	event := crashEvent{HistoryCount: historySize + 1}
	if _, err := makeCrashReport(event); err == nil {
		t.Fatal("makeCrashReport() accepted an invalid history count")
	}
}

func TestFatalExitFilter(t *testing.T) {
	tests := []struct {
		name   string
		status int32
		want   bool
	}{
		{name: "segv", status: int32(syscall.SIGSEGV), want: true},
		{name: "kill", status: int32(syscall.SIGKILL), want: true},
		{name: "exit code two", status: 2 << 8, want: true},
		{name: "exit code one", status: 1 << 8},
		{name: "clean exit", status: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := crashEvent{ExitStatus: tt.status}
			if got := isFatalExit(event); got != tt.want {
				t.Errorf("isFatalExit() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestSaveCrashReport(t *testing.T) {
	dir := t.TempDir()
	report := crashReport{
		Pid:        42,
		Process:    "worker",
		CrashName:  "SIGSEGV",
		OccurredAt: time.Date(2026, 11, 18, 1, 38, 10, 123, time.UTC),
	}

	path, err := saveCrashReport(dir, report)
	if err != nil {
		t.Fatalf("saveCrashReport() error = %v", err)
	}
	if !strings.Contains(filepath.Base(path), "worker_SIGSEGV_pid42.json") {
		t.Errorf("unexpected report filename %q", filepath.Base(path))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat report: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("report permissions = %04o, want 0600", got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var saved crashReport
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("decode saved report: %v", err)
	}
	if saved.CrashName != report.CrashName || !saved.OccurredAt.Equal(report.OccurredAt) {
		t.Errorf("saved report metadata = (%q, %v), want (%q, %v)",
			saved.CrashName, saved.OccurredAt, report.CrashName, report.OccurredAt)
	}
}

func TestCrashName(t *testing.T) {
	tests := []struct {
		name   string
		report crashReport
		want   string
	}{
		{name: "segv", report: crashReport{Signal: uint8(syscall.SIGSEGV)}, want: "SIGSEGV"},
		{name: "abort", report: crashReport{Signal: uint8(syscall.SIGABRT)}, want: "SIGABRT"},
		{name: "exit code", report: crashReport{ExitCode: 2}, want: "exit-code-2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := crashName(tt.report); got != tt.want {
				t.Errorf("crashName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSafeFilePart(t *testing.T) {
	if got := safeFilePart("../worker"); got != "___worker" {
		t.Errorf("safeFilePart() = %q, want %q", got, "___worker")
	}
}
