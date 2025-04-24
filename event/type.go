package event

import (
	"net"
	"time"
)

type TcpEvent struct {
    Comm   [16]uint8
    Pid    uint32     
    Uid    uint32    
    Sport  uint16     
    Dport  uint16 
    Saddr  uint32
    Daddr  uint32     
	TsUs   uint64
}
// Event is a common event interface
type Event struct {
	TsUs uint64
	Pid  uint32
	UID  uint32
	Af   uint16 // Address Family
	Task [16]byte
}

// IP4Event represents a socket connect event from AF_INET(4)
type IP4Event struct {
	Event
	Daddr uint32
	Dport uint16
}

// IP6Event represents a socket connect event from AF_INET6
type IP6Event struct {
	Event
	Daddr1 uint64
	Daddr2 uint64
	Dport  uint16
}

// OtherSocketEvent represents the socket connects that are not AF_INET, AF_INET6 or AF_UNIX
type OtherSocketEvent struct {
	Event
}

type EventPayload struct {
	// KernelTime    string  `json:"kernelTime"`
	UTime        time.Time `json:"uTime"`
	AddressFamily string `json:"addressFamily"`
	Pid           uint32 `json:"pid"`
	ProcessPath   string `json:"processPath"`
	ProcessArgs   string `json:"processArgs"`
	User          string `json:"user"`
	Comm          string `json:"comm"`
	Host          string `json:"host"`
	DestIP        net.IP `json:"dip"`
	DestPort      uint16 `json:"dport"`
	SrcIP         net.IP `json:"sip"`
	SrcPort       uint16 `json:"sport"`
	State	      string `json:"state"`
	ConatinerName string `json:"conatinerName"`
}