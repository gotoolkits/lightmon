package main

import (
	"fmt"
	"os"
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

func Runtime_Verifier() bool{
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