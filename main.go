//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"lightMon-ebpf/conv"
	"lightMon-ebpf/dockerinfo"
	. "lightMon-ebpf/event"
	"lightMon-ebpf/linux"
	. "lightMon-ebpf/outputer"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-16 -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 bpf sysEnterConnectSrc.c -- -Iheaders/

type Config struct {
	IPv6            bool   `yaml:"ipv6"`
	K8s             bool   `yaml:"k8s"`
	Format          string `yaml:"format"`
	DockerRuntime   string `yaml:"docker_runtime"`
	DockerData      string `yaml:"docker_data"`
	ExcludeFilter   string `yaml:"exclude"`
	LogPath         string `yaml:"logPath"`
}

var (
	outputer IOutputer
	config Config
)

func main() {
	initConfigs()
    
	// First load docker info to cache
	dockerinfo.LoadContainerInfosToCache(config.DockerRuntime, config.DockerData)
	// Cycle to load docker info to cache
	go runForLocalDockerInfos()

	setupBpfWorkers()
}

func loadConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &config)
}

func initConfigs() {
	// parse console args
	var configPath string
	flag.BoolVar(&config.IPv6, "v6", false, "print ipv6")
	flag.BoolVar(&config.K8s, "k8s", false, "k8s mode or docker mode")
	flag.StringVar(&config.Format, "f", "logfile", "table、json or logfile output format")
	flag.StringVar(&config.LogPath, "log_path", "/data/lightMon-ebpf/logs", "specify logfile output path")
	flag.StringVar(&config.DockerRuntime, "docker_runtime", "/run/docker", "docker runtime dir path")
	flag.StringVar(&config.DockerData, "docker_data", "/data/docker", "docker data dir path")
	flag.StringVar(&config.ExcludeFilter, "exclude", "", "exclude output filter")
	flag.StringVar(&configPath, "c", "config.yaml", "config file path")
	flag.Parse()

	// Load config from file if exists
	if _, err := os.Stat(configPath); err == nil {
		if err := loadConfig(configPath); err != nil {
			log.Printf("Failed to load config file: %v, using default values", err)
		}
	}

	Set_Docker_Path(config.DockerRuntime, config.DockerData)
	if ok := Runtime_Verifier(); !ok {
		fmt.Println("Docker Runtime Verifier failed. please use -docker_runtime and -docker_data args to specify docker env path.")
		os.Exit(1)
	}

	dockerinfo.SetDockerMode(config.K8s)
	dockerinfo.NewLocalCaches()

	outputer = NewOutputer(config.IPv6, config.Format, config.ExcludeFilter,config.LogPath)

}


func runForLocalDockerInfos(){
	dockerinfo.RunWithInterval(10, config.DockerRuntime, config.DockerData, dockerinfo.LoadContainerInfosToCache)
}
func setupBpfWorkers() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Load eBPF program
	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceTcpEvent, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %s", err)
	}
	defer tp.Close()

	rd4, err := perf.NewReader(objs.Ipv4Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd4.Close()

	rd6, err := perf.NewReader(objs.Ipv6Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd6.Close()

	rdOther, err := perf.NewReader(objs.OtherSocketEvents, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rdOther.Close()

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd4.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}

		if err := rd6.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}

		if err := rdOther.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	outputer.PrintHeader()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go (func() {
		for {
			if !readIP4Events(rd4) {
				return
			}
		}
	})()

	go (func() {
		for {
			if !readIP6Events(rd6) {
				return
			}
		}
	})()

	go (func() {
		for {
			if !readOtherEvents(rdOther) {
				return
			}
		}
	})()

	<-sig
}

func readIP4Events(rd *perf.Reader) bool {
	var event IP4Event
	record, err := rd.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return false
		}
		log.Printf("reading from perf event reader: %s", err)
		return true
	}

	if record.LostSamples != 0 {
		log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
		return true
	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("parsing perf event: %s", err)
		return true
	}

	eventPayload := newGenericEventPayload(&event.Event)
	eventPayload.DestIP = conv.ToIP4(event.Daddr)
	eventPayload.DestPort = event.Dport
	outputer.PrintLine(eventPayload)
	return true
}

func readIP6Events(rd *perf.Reader) bool {
	var event IP6Event
	record, err := rd.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return false
		}
		log.Printf("reading from perf event reader: %s", err)
		return true
	}

	if record.LostSamples != 0 {
		log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
		return true
	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("parsing perf event: %s", err)
		return true
	}

	eventPayload := newGenericEventPayload(&event.Event)
	eventPayload.DestIP = conv.ToIP6(event.Daddr1, event.Daddr2)
	eventPayload.DestPort = event.Dport
	outputer.PrintLine(eventPayload)
	return true
}

func readOtherEvents(rd *perf.Reader) bool {
	var event OtherSocketEvent
	record, err := rd.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return false
		}
		log.Printf("reading from perf event reader: %s", err)
		return true
	}

	if record.LostSamples != 0 {
		log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
		return true
	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("parsing perf event: %s", err)
		return true
	}

	eventPayload := newGenericEventPayload(&event.Event)
	outputer.PrintLine(eventPayload)
	return true
}

func newGenericEventPayload(event *Event) EventPayload {
	username := strconv.Itoa(int(event.UID))
	user, err := user.LookupId(username)
	if err != nil {
		log.Printf("Could not lookup user with id: %d", event.UID)
	} else {
		username = user.Username
	}



	pid := int(event.Pid)
	pidStr :=strconv.Itoa(pid)
	contname:= dockerinfo.GetContainerNameFromConnProcessCacheByPid(pidStr)

	payload := EventPayload{
		KernelTime:    strconv.Itoa(int(event.TsUs)),
		GoTime:        time.Now(),
		AddressFamily: conv.ToAddressFamily(int(event.Af)),
		Pid:           event.Pid,
		ProcessPath:   linux.ProcessPathForPid(pid),
		ProcessArgs:   linux.ProcessArgsForPid(pid),
		User:          username,
		Comm:          unix.ByteSliceToString(event.Task[:]),
		ConatinerName: contname,
	}
	return payload
}




