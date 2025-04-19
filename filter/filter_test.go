package filter

import (
	"net"
	"testing"

	. "lightMon-ebpf/event"
)

func TestPortFilter_Match(t *testing.T) {
	tests := []struct {
		name     string
		port     uint16
		event    EventPayload
		expected bool
	}{
		{
			name: "match port",
			port: 80,
			event: EventPayload{
				DestPort: 80,
			},
			expected: true,
		},
		{
			name: "not match port",
			port: 80,
			event: EventPayload{
				DestPort: 443,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &PortFilter{port: tt.port}
			if got := f.Match(tt.event); got != tt.expected {
				t.Errorf("PortFilter.Match() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIPFilter_Match(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		event    EventPayload
		expected bool
	}{
		{
			name: "match ip",
			ip:   "192.168.1.1",
			event: EventPayload{
				DestIP: net.ParseIP("192.168.1.1"),
			},
			expected: true,
		},
		{
			name: "not match ip",
			ip:   "192.168.1.1",
			event: EventPayload{
				DestIP: net.ParseIP("10.0.0.1"),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &IPFilter{ip: tt.ip}
			if got := f.Match(tt.event); got != tt.expected {
				t.Errorf("IPFilter.Match() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCIDRFilter_Match(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")
	
	tests := []struct {
		name     string
		ipNet    *net.IPNet
		event    EventPayload
		expected bool
	}{
		{
			name:  "match cidr",
			ipNet: ipNet,
			event: EventPayload{
				DestIP: net.ParseIP("192.168.1.100"),
			},
			expected: true,
		},
		{
			name:  "not match cidr",
			ipNet: ipNet,
			event: EventPayload{
				DestIP: net.ParseIP("10.0.0.1"),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &CIDRFilter{ipNet: tt.ipNet}
			if got := f.Match(tt.event); got != tt.expected {
				t.Errorf("CIDRFilter.Match() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestKeywordFilter_Match(t *testing.T) {
	tests := []struct {
		name     string
		keyword  string
		event    EventPayload
		expected bool
	}{
		{
			name:    "match keyword",
			keyword: "nginx",
			event: EventPayload{
				ProcessPath: "/usr/sbin/nginx",
			},
			expected: true,
		},
		{
			name:    "not match keyword",
			keyword: "nginx",
			event: EventPayload{
				ProcessPath: "/usr/sbin/apache",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &KeywordFilter{keyword: tt.keyword}
			if got := f.Match(tt.event); got != tt.expected {
				t.Errorf("KeywordFilter.Match() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExcludeFilter_ShouldExclude(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")
	
	tests := []struct {
		name     string
		groups   []FilterGroup
		event    EventPayload
		expected bool
	}{
		{
			name: "AND group match",
			groups: []FilterGroup{
				{
					filters: []FilterCondition{
						&PortFilter{port: 80},
						&IPFilter{ip: "192.168.1.1"},
					},
					op: "&&",
				},
			},
			event: EventPayload{
				DestPort: 80,
				DestIP:   net.ParseIP("192.168.1.1"),
			},
			expected: true,
		},
		{
			name: "OR group match",
			groups: []FilterGroup{
				{
					filters: []FilterCondition{
						&PortFilter{port: 80},
						&IPFilter{ip: "192.168.1.1"},
					},
					op: "||",
				},
			},
			event: EventPayload{
				DestPort: 443,
				DestIP:   net.ParseIP("192.168.1.1"),
			},
			expected: true,
		},
		{
			name: "multiple groups",
			groups: []FilterGroup{
				{
					filters: []FilterCondition{
						&PortFilter{port: 80},
						&IPFilter{ip: "192.168.1.1"},
					},
					op: "&&",
				},
				{
					filters: []FilterCondition{
						&CIDRFilter{ipNet: ipNet},
					},
					op: "||",
				},
			},
			event: EventPayload{
				DestPort: 443,
				DestIP:   net.ParseIP("192.168.1.100"),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ef := &ExcludeFilter{groups: tt.groups}
			if got := ef.ShouldExclude(tt.event); got != tt.expected {
				t.Errorf("ExcludeFilter.ShouldExclude() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseExcludeParam(t *testing.T) {
	tests := []struct {
		name     string
		param    string
		event    EventPayload
		expected bool
	}{
		{
			name:  "single port condition",
			param: "dport=80",
			event: EventPayload{
				DestPort: 80,
			},
			expected: true,
		},
		{
			name:  "AND conditions",
			param: "dport=80 && dip='192.168.1.1'",
			event: EventPayload{
				DestPort: 80,
				DestIP:   net.ParseIP("192.168.1.1"),
			},
			expected: true,
		},
		{
			name:  "OR conditions",
			param: "dport=80; dip='192.168.1.1'",
			event: EventPayload{
				DestPort: 443,
				DestIP:   net.ParseIP("192.168.1.1"),
			},
			expected: true,
		},
		{
			name:  "CIDR condition",
			param: "dip='192.168.1.0/24'",
			event: EventPayload{
				DestIP: net.ParseIP("192.168.1.100"),
			},
			expected: true,
		},
		{
			name:  "keyword condition",
			param: "keyword='nginx'",
			event: EventPayload{
				ProcessPath: "/usr/sbin/nginx",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := ParseExcludeParam(tt.param)
			if got := filter.ShouldExclude(tt.event); got != tt.expected {
				t.Errorf("ParseExcludeParam() result = %v, want %v", got, tt.expected)
			}
		})
	}
}