package outputer

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	. "github.com/gotoolkits/lightmon/event"

	"github.com/stretchr/testify/assert"
)

func TestNewOutputer(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		wantType interface{}
	}{
		{"json format", "json", &jsonOutput{}},
		{"logfile format", "logfile", &logFileOutput{}},
		{"default table format", "", &tableOutput{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewOutputer(false, tt.format, "","")
			assert.IsType(t, tt.wantType, got)
		})
	}
}

func TestJsonOutput_PrintLine(t *testing.T) {
	tests := []struct {
		name        string
		ipv6        bool
		event       EventPayload
		shouldPrint bool
	}{
		{"ipv4 event", false, EventPayload{AddressFamily: "AF_INET"}, true},
		{"ipv6 event with ipv6 disabled", false, EventPayload{AddressFamily: "AF_INET6"}, false},
		{"ipv6 event with ipv6 enabled", true, EventPayload{AddressFamily: "AF_INET6"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			defer func() { os.Stdout = oldStdout }()

			outputer := &jsonOutput{ipv6: tt.ipv6}
			outputer.PrintLine(tt.event)

			w.Close()
			var buf bytes.Buffer
			io.Copy(&buf, r)

			if tt.shouldPrint {
				assert.NotEmpty(t, buf.String())
				var result EventPayload
				assert.NoError(t, json.Unmarshal(buf.Bytes(), &result))
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

func TestTableOutput_PrintLine(t *testing.T) {
	tests := []struct {
		name        string
		ipv6        bool
		event       EventPayload
		shouldPrint bool
	}{
		{"ipv4 event", false, EventPayload{
			AddressFamily: "AF_INET",
			UTime:       time.Now(),
			User:         "test",
			Pid:          123,
			DestIP:       []byte{127, 0, 0, 1},
			DestPort:     8080,
			ProcessPath:  "/bin/test",
			ProcessArgs:  "arg1 arg2",
		}, true},
		{"ipv6 event with ipv6 disabled", false, EventPayload{
			AddressFamily: "AF_INET6",
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			defer func() { os.Stdout = oldStdout }()

			outputer := &tableOutput{ipv6: tt.ipv6}
			outputer.PrintLine(tt.event)

			w.Close()
			var buf bytes.Buffer
			io.Copy(&buf, r)

			if tt.shouldPrint {
				assert.Contains(t, buf.String(), "test")
				assert.Contains(t, buf.String(), "8080")
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

func TestTableOutput_PrintHeader(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	outputer := &tableOutput{}
	outputer.PrintHeader()

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	assert.Contains(t, buf.String(), "TIME")
	assert.Contains(t, buf.String(), "USER")
	assert.Contains(t, buf.String(), "PID")
}