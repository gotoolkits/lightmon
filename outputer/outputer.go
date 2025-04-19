package outputer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	. "github.com/gotoolkits/lightmon/event"
	"github.com/gotoolkits/lightmon/filter"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	log "github.com/sirupsen/logrus"
)

type IOutputer interface {
	PrintHeader()
	PrintLine(EventPayload)
}

func NewOutputer(ipv6 bool, format string, excludeParam string,logPath string) IOutputer {
	if format == "json" {
		return newJsonOutput(ipv6, excludeParam)
	}
	if format == "logfile" {
		return newLogFileOutput(ipv6, excludeParam,logPath)
	}
	return newTableOutput(ipv6, excludeParam)
}

// log file outputer
type logFileOutput struct {
	ipv6 bool
	excludeParam string
	logger *log.Logger
}

func newLogFileOutput(ipv6 bool, excludeParam string,logPath string) IOutputer {
	rl, err := rotatelogs.New(
		logPath+"/lightmon.log.%Y%m%d%H%M",
		rotatelogs.WithRotationTime(time.Duration(60)*time.Minute),
		// rotatelogs.WithLinkName("lightmon.log"),
		rotatelogs.WithRotationCount(8),
	)
	if err != nil {
		panic(err)
	}

	// init logrus instance
	logger := log.New()
	logger.SetOutput(rl)
	logger.SetFormatter(&log.JSONFormatter{})

	return &logFileOutput{
		ipv6: ipv6,
		excludeParam: excludeParam,
		logger: logger,
	}
}
func (l logFileOutput) PrintHeader() {
	// no need
}
func (l logFileOutput) PrintLine(e EventPayload) {
	if e.AddressFamily == "AF_INET6" && !l.ipv6 {
		return
	}
	
	if l.excludeParam != "" {
		filter := filter.ParseExcludeParam(l.excludeParam)
		if filter.ShouldExclude(e) {
			return
		}
	}

	ipv6 := 0
	if e.AddressFamily == "AF_INET6" {
		ipv6 = 1
	}

	logF:= log.Fields{
		"user": e.User,
		"pid": strconv.Itoa(int(e.Pid)),
		"procPath":e.ProcessPath,
		"procArgs": e.ProcessArgs,
		"ipv6": ipv6,
		"dip": e.DestIP.String(),
		"dport": strconv.Itoa(int(e.DestPort)),
		"conatiner": e.ConatinerName,
	}

	l.logger.WithFields(logF).Info()
}



// console json outputer
type jsonOutput struct {
	ipv6 bool
	excludeParam string
}
func newJsonOutput(ipv6 bool, excludeParam string) IOutputer {
	return &jsonOutput{ipv6, excludeParam}
}
func (j jsonOutput) PrintHeader() {}
func (j jsonOutput) PrintLine(e EventPayload) {
	if (e.AddressFamily == "AF_INET6"){
		if !j.ipv6 {
			return
		}
	}
	
	if j.excludeParam != "" {
		filter := filter.ParseExcludeParam(j.excludeParam)
		if filter.ShouldExclude(e) {
			return
		}
	}

	jsonEvent,err:= json.Marshal(e)
	if err != nil {
		fmt.Printf("{'ERROR':%s}",err)
	}
	fmt.Println(string(jsonEvent))
}


// console table outputer
type tableOutput struct {
	ipv6 bool
	excludeParam string
}
func newTableOutput(ipv6 bool, excludeParam string) IOutputer {
	return &tableOutput{ipv6, excludeParam}
}
func (t tableOutput) PrintHeader() {
	var header string
	var args []interface{}

	header = "%-9s %-16s %-10s %-9s %-42s %-20s %s\n"
	args = []interface{}{"TIME", "USER", "PID", "AF", "DESTINATION","CONTAINER", "PROCESS"}

	fmt.Printf(header, args...)
}

func (t tableOutput) PrintLine(e EventPayload) {
	if t.excludeParam != "" {
		filter := filter.ParseExcludeParam(t.excludeParam)
		if filter.ShouldExclude(e) {
			return
		}
	}
	time := e.GoTime.Format("15:04:05")
	dest := e.DestIP.String() + " " + strconv.Itoa(int(e.DestPort))

	var header string
	var args []interface{}
	var addrFamily = ""

	if (e.AddressFamily == "AF_INET"){
		addrFamily = "ipv4"
	}
	if (e.AddressFamily == "AF_INET6"){ 
		addrFamily = "ipv6"
		if !t.ipv6 {
			return
		}
	}

	header = "%-9s %-16s %-10d %-9s %-42s %-20s %s\n"
	args = []interface{}{time, e.User, e.Pid, addrFamily, dest,e.ConatinerName,e.ProcessPath + " " + e.ProcessArgs}


	fmt.Printf(header, args...)
}



