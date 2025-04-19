package dockerinfo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrInvalidPath     = errors.New("invalid path")
	ErrReadFile        = errors.New("read file failed")
	ErrProcessNotFound = errors.New("process not found")


	// DOCKER_RUNTIME_DIR string = "/run/docker"
	// DOCKER_DATA_DIR string = "/var/lib/docker"
)

// DockerInfo 结构体用于存储和管理Docker容器信息
type DockerInfo struct {
	DockerRootDir string // Docker运行时主目录
	DataDir       string // Docker数据目录
}

// ContainerInfo 结构体用于存储单个容器的信息
type ContainerInfo struct {
	ID        string // 容器ID
	Name      string // 容器名称
	ParentPID string // 父进程ID（容器进程ID）
	InitPID   string // 初始进程ID
}

// NewDockerInfo 创建DockerInfo实例
func NewDockerInfoWithPath(dockerRuntimeDir string,dockerDataDir string) *DockerInfo {
	if dockerRuntimeDir == "" {
		dockerRuntimeDir = "/run/docker" // 默认Docker运行时主目录
	}
	if dockerDataDir == "" {
		dockerDataDir = "/var/lib/docker" // 默认Docker数据目录
	}
	return &DockerInfo{
		DockerRootDir: dockerRuntimeDir,
		DataDir:       dockerDataDir, 
	}
}

// GetContainerIDs 获取所有运行中的容器ID列表
func (d *DockerInfo) GetContainerIDs() ([]string, error) {
	containerdPath := filepath.Join(d.DockerRootDir, "/containerd")
	entries, err := os.ReadDir(containerdPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}

	var containerIDs []string
	for _, entry := range entries {
		// 只获取一级目录
		if entry.IsDir() {
			containerIDs = append(containerIDs, entry.Name())
		}
	}

	return containerIDs, nil
}

// GetInitProcessPID 从state.json文件中提取容器的初始进程ID
func (d *DockerInfo) GetInitProcessPID(containerID string) (string, error) {
	statePath := filepath.Join(d.DockerRootDir, "/runtime-runc/moby", containerID, "state.json")
	file, err := os.Open(statePath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrReadFile, err)
	}
	defer file.Close()

	// 读取文件内容
	buf := make([]byte, 1024) // 增加缓冲区大小
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("%w: %v", ErrReadFile, err)
	}

	// 使用字符串处理方式提取init_process_pid值
	content := string(buf[:n])
	const pidKey = "\"init_process_pid\":"
	pidStart := strings.Index(content, pidKey)
	if pidStart == -1 {
		return "", fmt.Errorf("%w: init_process_pid not found", ErrReadFile)
	}

	// 跳过key，找到数值开始的位置
	pidStart += len(pidKey)
	// 跳过可能的空白字符
	for pidStart < len(content) && (content[pidStart] == ' ' || content[pidStart] == '\t' || content[pidStart] == '\n' || content[pidStart] == '\r') {
		pidStart++
	}

	// 查找PID结束位置（逗号或右大括号）
	pidEnd := pidStart
	for pidEnd < len(content) && content[pidEnd] >= '0' && content[pidEnd] <= '9' {
		pidEnd++
	}

	if pidEnd == pidStart {
		return "", fmt.Errorf("%w: invalid PID format", ErrReadFile)
	}

	// 提取PID值
	return content[pidStart:pidEnd], nil
}



// GetContainerName 从config.v2.json文件中获取容器名称
func (d *DockerInfo) GetContainerName(containerID string) (string, error) {
	configPath := filepath.Join(d.DataDir, "containers", containerID, "config.v2.json")
	file, err := os.Open(configPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrReadFile, err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	var content strings.Builder
	
	// 逐块读取文件内容
	for {
		chunk, err := reader.ReadString('\n')
		content.WriteString(chunk)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrReadFile, err)
		}
		// 如果已经找到了 "Name" 字段，可以提前退出
		if strings.Contains(content.String(), "\"Name\":") {
			break
		}
	}

	// 使用字符串处理方式提取Name值
	contentStr := content.String()
	const nameKey = "\"Name\":"
	nameStart := strings.Index(contentStr, nameKey)
	if nameStart == -1 {
		return "", fmt.Errorf("%w: container name not found", ErrReadFile)
	}

	// 跳过key，找到值的开始位置（第一个引号）
	nameStart += len(nameKey)
	nameStart = strings.Index(contentStr[nameStart:], "\"") + nameStart + 1
	if nameStart == -1 {
		return "", fmt.Errorf("%w: invalid container name format", ErrReadFile)
	}

	// 找到值的结束位置（下一个引号）
	nameEnd := strings.Index(contentStr[nameStart:], "\"") + nameStart
	if nameEnd == -1 {
		return "", fmt.Errorf("%w: invalid container name format", ErrReadFile)
	}

	return contentStr[nameStart:nameEnd], nil
}

// GetContainerInfo 获取指定容器ID的完整信息
func (d *DockerInfo) GetContainerInfo(containerID string) (*ContainerInfo, error) {
	// 获取初始进程ID
	initPID, err := d.GetInitProcessPID(containerID)
	if err != nil {
		return nil, err
	}

	// 获取父进程ID（容器进程ID）
	parentPID, err := GetPPID(initPID)
	if err != nil {
		return nil, err
	}

	// 获取容器名称
	name, err := d.GetContainerName(containerID)
	if err != nil {
		// 如果获取名称失败，使用空字符串，但不中断整个流程
		fmt.Printf("获取容器 %s 名称失败: %v\n", containerID, err)
		name = ""
	}

	return &ContainerInfo{
		ID:        containerID,
		Name:      name,
		InitPID:   initPID,
		ParentPID: parentPID,
	}, nil
}

// GetAllContainersInfo 获取所有运行中容器的信息
func (d *DockerInfo) GetAllContainersInfo() ([]*ContainerInfo, error) {
	// 获取所有容器ID
	containerIDs, err := d.GetContainerIDs()
	if err != nil {
		return nil, err
	}

	var containersInfo []*ContainerInfo
	for _, id := range containerIDs {
		info, err := d.GetContainerInfo(id)
		if err != nil {
			// 记录错误但继续处理其他容器
			fmt.Printf("获取容器 %s 信息失败: %v\n", id, err)
			continue
		}
		containersInfo = append(containersInfo, info)
	}

	return containersInfo, nil
}


// GetPPID 获取指定进程ID的父进程ID
func GetPPID(pid string) (string, error) {
	statusPath := filepath.Join("/proc", pid, "status")
	file, err := os.Open(statusPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrProcessNotFound, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrReadFile, err)
	}

	return "", ErrProcessNotFound
}

func GetRootParentPID(pid string) (string, error) {
    currentPID := pid
    visited := make(map[string]bool) 

    for {
        if visited[currentPID] {
            return "", fmt.Errorf("detected a cycle in parent process hierarchy")
        }
        visited[currentPID] = true

        ppid, err := GetPPID(currentPID)
        if err != nil {
            return "", fmt.Errorf("failed to get parent PID for %s: %w", currentPID, err)
        }

        if ppid == "1" {
            return currentPID, nil
        }
        currentPID = ppid
    }
}

func GetRootPrevParentPID(pid string) (string, error) {
    currentPID := pid
    visited := make(map[string]bool) 
	prevPID := ""

    for {
        if visited[currentPID] {
            return "", fmt.Errorf("detected a cycle in parent process hierarchy")
        }
        visited[currentPID] = true

        ppid, err := GetPPID(currentPID)
        if err != nil {
            return "", fmt.Errorf("failed to get parent PID for %s: %w", currentPID, err)
        }

        if ppid == "1" {
			if prevPID == "" {
                return currentPID, nil
            }
            return prevPID, nil
        }

		prevPID = currentPID
        currentPID = ppid
    }
}

// GetChildrenPIDs 获取指定进程ID的所有子进程ID（包括子子进程）
func GetChildrenPIDs(pid string) ([]string, error) {
	if _, err := os.Stat(filepath.Join("/proc", pid)); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrProcessNotFound, err)
	}

	childrenPIDs := make([]string, 0)
	visited := make(map[string]bool) // 用于防止循环引用

	// 递归获取子进程
	var getChildren func(parentPID string) error
	getChildren = func(parentPID string) error {
		if visited[parentPID] {
			return nil
		}
		visited[parentPID] = true


		taskPath := filepath.Join("/proc", parentPID, "task")
		tasks, err := os.ReadDir(taskPath)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrProcessNotFound, err)
		}

		// 遍历每个task的children文件
		for _, task := range tasks {
			childrenPath := filepath.Join(taskPath, task.Name(), "children")
			content, err := os.ReadFile(childrenPath)
			if err != nil {
				continue
			}

			// 解析children文件内容
			if len(content) > 0 {
				// 将内容转换为字符串并分割
				children := strings.Fields(string(content))
				for _, child := range children {
					childrenPIDs = append(childrenPIDs, child)
					// 递归获取子进程的子进程
					if err := getChildren(child); err != nil {
						fmt.Printf("获取进程 %s 的子进程失败: %v\n", child, err)
					}
				}
			}
		}
		return nil
	}

	// 开始递归获取所有子进程
	err := getChildren(pid)
	if err != nil {
		return nil, err
	}

	return childrenPIDs, nil
}


func RunWithInterval(interval int,dockerRuntimeDir string,dockerDataDir string,fn func (string,string) error) {
	 var errCount = 0 
	 var maxTries = 5

      for {
		 err := fn(dockerRuntimeDir,dockerDataDir)
		 if err!=nil {
			fmt.Println(err)
			errCount++ 

			if errCount > maxTries {
				break
			}
			continue
		 }
		time.Sleep(time.Duration(interval) * time.Second)
	  }
}