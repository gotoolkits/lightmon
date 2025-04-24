package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var (
	SYS_ENTER_CONNECT string  = "/sys/kernel/debug/tracing/events/syscalls/sys_enter_connect"
	DOCKER_RUNTIME_DIR string = "/run/docker"
	DOCKER_DATA_DIR string = "/data/docker"
)

func Set_Docker_Path(docker_rumtime,docker_data string) {
	DOCKER_RUNTIME_DIR = docker_rumtime
	DOCKER_DATA_DIR = docker_data
}

func Runtime_Verifier(ebpf int) bool{
	if ebpf == 0  {
		if ok,err:=isFunctionAvailable("tcp_connect");!ok {
			fmt.Println("ERROR: ",err)
			return false
		}
	} else {
		if ok,err:=PathExists(SYS_ENTER_CONNECT);!ok{
			fmt.Println("ERROR: ",err)
			return false
		}
	}

	if ok,err:=PathExists(SYS_ENTER_CONNECT);!ok{
		fmt.Println("ERROR: ",err)
		return false
	}

	if ok,err:=PathExists(DOCKER_RUNTIME_DIR);!ok{
		fmt.Println("ERROR: ",err)
		return false
		
	}

	if ok,err:=PathExists(DOCKER_DATA_DIR);!ok{
		fmt.Println("ERROR: ",err)
		return false
	}

	return true
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, err
	}
	return false, err
}

func isFunctionAvailable(functionName string) (bool, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return false, fmt.Errorf("failed to open /proc/kallsyms: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
	
		if fields[2] == functionName {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("error reading /proc/kallsyms: %v", err)
	}

	return false, nil
}