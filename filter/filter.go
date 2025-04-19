package filter

import (
	"net"
	"strconv"
	"strings"

	. "lightMon-ebpf/event"
)



type FilterCondition interface {
	Match(e EventPayload) bool
}


type PortFilter struct {
	port uint16
}
func (f *PortFilter) Match(e EventPayload) bool {
	return e.DestPort == f.port
}


type IPFilter struct {
	ip string
}
func (f *IPFilter) Match(e EventPayload) bool {
	return e.DestIP.String() == f.ip
}

type CIDRFilter struct {
	ipNet *net.IPNet
}
func (f *CIDRFilter) Match(e EventPayload) bool {
	return f.ipNet.Contains(e.DestIP)
}


type KeywordFilter struct {
	keyword string
}
func (f *KeywordFilter) Match(e EventPayload) bool {
	return strings.Contains(e.ProcessPath, f.keyword)
}

type ContainerNameFilter struct {
	keyword string
}
func (f *ContainerNameFilter) Match(e EventPayload) bool {
	return strings.Contains(e.ConatinerName, f.keyword)
}


type FilterGroup struct {
	filters []FilterCondition
	op      string // "&&" or "||"
}

type ExcludeFilter struct {
	groups []FilterGroup
}

func (ef *ExcludeFilter) AddGroup(filters []FilterCondition, op string) {
	ef.groups = append(ef.groups, FilterGroup{filters: filters, op: op})
}

func (ef *ExcludeFilter) ShouldExclude(e EventPayload) bool {
	for _, group := range ef.groups {
		groupResult := false
		if group.op == "&&" {
			groupResult = true
			for _, filter := range group.filters {
				if !filter.Match(e) {
					groupResult = false
					break
				}
			}
		} else { // "||" is default
			for _, filter := range group.filters {
				if filter.Match(e) {
					groupResult = true
					break
				}
			}
		}
		if groupResult {
			return true
		}
	}
	return false
}

func ParseExcludeParam(param string) *ExcludeFilter {
	ef := &ExcludeFilter{}
	
	// Split by logical operators first
	groups := strings.Split(param, ";")
	
	for _, groupStr := range groups {
		groupStr = strings.TrimSpace(groupStr)
		if groupStr == "" {
			continue
		}
		
		// Determine operator
		var op string
		if strings.Contains(groupStr, " && ") {
			op = "&&"
		} else {
			op = "||"
		}
		
		// Split conditions
		var filters []FilterCondition
		conditions := strings.Split(groupStr, op)
		
		for _, cond := range conditions {
			cond = strings.TrimSpace(cond)
			kv := strings.SplitN(cond, "=", 2)
			if len(kv) != 2 {
				continue
			}
			
			key := strings.TrimSpace(kv[0])
			value := strings.Trim(strings.TrimSpace(kv[1]), "'\"")
			
			switch key {
			case "dport":
				port, _ := stringToUint16(value)
				filters = append(filters, &PortFilter{port: port})
			case "dip":
				if strings.Contains(value, "/") {
					_, ipNet, err := net.ParseCIDR(value)
					if err == nil {
						filters = append(filters, &CIDRFilter{ipNet: ipNet})
					} else {
						filters = append(filters, &IPFilter{ip: value})
					}
				} else {
					filters = append(filters, &IPFilter{ip: value})
				}
			case "keyword":
				filters = append(filters, &KeywordFilter{keyword: value})
			case "container":
				filters = append(filters, &ContainerNameFilter{keyword: value})
			}
		}
		
		if len(filters) > 0 {
			ef.AddGroup(filters, op)
		}
	}
	
	return ef
}

func stringToUint16(s string) (uint16, error) {
	num, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(num), nil
}

