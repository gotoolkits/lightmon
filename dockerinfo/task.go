package dockerinfo

import (
	"fmt"
	"time"

	"github.com/fanjindong/go-cache"
)


var LocalCachesInst *LocalCaches
var DefualtDockerCacheExpTime time.Duration = 5*time.Minute
var DefualtConnProccessCacheExpTime time.Duration = 5*time.Minute
var docker_mode = "k8s"


func NewLocalCaches() {
	LocalCachesInst = InitLocalCaches()
}

func SetDockerMode(k8s bool){
	if k8s {
		docker_mode = "k8s"
	} else {
		docker_mode = "docker"
	}	
}

//
// LoadContainerInfosToCache
// make mapping for container initPid、ppid、childPids with container_info
// 
func LoadContainerInfosToCache(dockerRuntimeDir string,dockerDataDir string) error{
	dckinst := NewDockerInfoWithPath(dockerRuntimeDir,dockerDataDir)
	infos,err:= dckinst.GetAllContainersInfo()
	if err != nil {
		return err 
	}

	for _,info:= range infos {
		childPids,err:= GetChildrenPIDs(info.ParentPID)
		if err != nil {
			fmt.Println("ERROR: ",err)
		}

		if len(info.Name)>1 {
			info.Name = info.Name[1:]
		} 
	
		if !LocalCachesInst.RefreshContainerCache.Exists(info.InitPID) {
			LocalCachesInst.RefreshContainerCache.Set(info.InitPID,info,cache.WithEx(DefualtDockerCacheExpTime))
		}

		if !LocalCachesInst.RefreshContainerCache.Exists(info.ParentPID) {
			LocalCachesInst.RefreshContainerCache.Set(info.ParentPID,info,cache.WithEx(DefualtDockerCacheExpTime))
		}

		for _,pid := range childPids {
			if !LocalCachesInst.RefreshContainerCache.Exists(info.InitPID)  {
				LocalCachesInst.RefreshContainerCache.Set(pid,info,cache.WithEx(DefualtDockerCacheExpTime))
			}
		}
	}
	return nil
}


//
// GetContainerNameFromConnProcessCacheByPid
// get container name by pid using match container_cache
//
func GetContainerNameFromConnProcessCacheByPid(pid string) string {
	if !LocalCachesInst.RefreshProccessCache.Exists(pid) {

		// to match Container_cache by pid
		info,ok:=LocalCachesInst.RefreshContainerCache.Get(pid)
		if ok {
			containerName:= info.(*ContainerInfo).Name
			LocalCachesInst.RefreshProccessCache.Set(pid,containerName,cache.WithEx(DefualtConnProccessCacheExpTime))
			return containerName
		}

		// to match Container_cache by root ppid

		var ppid = "" 
		var err error

		if docker_mode == "k8s" {
			ppid,err =GetRootPrevParentPID(pid)
			if err != nil {
				fmt.Println("ERROR: ",err)
			}
		} else {
			ppid,err=GetRootParentPID(pid)
			if err != nil {
				fmt.Println("ERROR: ",err)
			}
		}

		if LocalCachesInst.RefreshContainerCache.Exists(ppid) {
			// match containers cache
			info,_:=LocalCachesInst.RefreshContainerCache.Get(ppid)
			containerName:= info.(*ContainerInfo).Name
			// update proccess cache
			LocalCachesInst.RefreshProccessCache.Set(pid,containerName,cache.WithEx(DefualtConnProccessCacheExpTime))
			return containerName
		}

		// 
		// err = LoadContainerInfosToCache()
		// if err !=nil {
		// 	fmt.Println("ERROR: ",err)
		// 	return "NULL"
		// }
		// info,ok:=LocalCachesInst.RefreshContainerCache.Get(pid)
		// if ok {
		// 	containerName:= info.(ContainerInfo).Name
		// 	LocalCachesInst.RefreshProccessCache.Set(pid,containerName,cache.WithEx(DefualtConnProccessCacheExpTime))
		// 	return containerName
		// }
		LocalCachesInst.RefreshProccessCache.Set(pid,"NULL")
		return "NULL"
		
	}
	
	containerName,_:=LocalCachesInst.RefreshProccessCache.Get(pid)
	return containerName.(string)
}



func SetDockerCacheExpTime(t time.Duration) {
	DefualtDockerCacheExpTime = t 
}


func SetProccessCacheExpTime(t time.Duration) {
	DefualtConnProccessCacheExpTime = t 
}