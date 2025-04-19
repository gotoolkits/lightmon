package dockerinfo

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// 创建临时测试目录和文件
func setupTestEnvironment(t *testing.T) (string, func()) {
	// 创建临时根目录
	tmpDir, err := os.MkdirTemp("", "docker-test-*")
	if err != nil {
		t.Fatal(err)
	}

	// 创建模拟的Docker运行时目录结构
	containerdPath := filepath.Join(tmpDir, "containerd")
	runtimePath := filepath.Join(tmpDir, "runtime-runc", "moby")
	procPath := filepath.Join(tmpDir, "proc")

	// 创建必要的目录
	if err := os.MkdirAll(containerdPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtimePath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(procPath, 0755); err != nil {
		t.Fatal(err)
	}

	// 返回清理函数
	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup
}

// 创建测试容器目录和状态文件
func createTestContainer(t *testing.T, rootDir, containerID string, initPID int) {
	// 创建容器目录
	containerDir := filepath.Join(rootDir, "containerd", containerID)
	if err := os.MkdirAll(containerDir, 0755); err != nil {
		t.Fatal(err)
	}

	// 创建state.json文件
	statePath := filepath.Join(rootDir, "runtime-runc", "moby", containerID, "state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0755); err != nil {
		t.Fatal(err)
	}

	stateContent := []byte(`{"init_process_pid": ` + strconv.Itoa(initPID) + `}`)
	if err := os.WriteFile(statePath, stateContent, 0644); err != nil {
		t.Fatal(err)
	}

	// 创建进程状态文件
	procDir := filepath.Join(rootDir, "proc", strconv.Itoa(initPID))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}

	// 创建status文件，设置父进程ID为initPID + 1
	statusContent := []byte("PPid:\t" + strconv.Itoa(initPID+1) + "\n")
	statusPath := filepath.Join(procDir, "status")
	if err := os.WriteFile(statusPath, statusContent, 0644); err != nil {
		t.Fatal(err)
	}
}

// 测试NewDockerInfo函数
func TestNewDockerInfo(t *testing.T) {
	tests := []struct {
		name     string
		rootDir  string
		expected string
	}{
		{
			name:     "使用默认目录",
			rootDir:  "",
			expected: "/run/docker/",
		},
		{
			name:     "使用自定义目录",
			rootDir:  "/custom/path/",
			expected: "/custom/path/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docker := NewDockerInfoWithPath(tt.rootDir,"")
			if docker.DockerRootDir != tt.expected {
				t.Errorf("期望目录 %s, 得到 %s", tt.expected, docker.DockerRootDir)
			}
		})
	}
}

// 测试GetContainerIDs方法
func TestGetContainerIDs(t *testing.T) {
	tmpDir, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// 创建测试容器目录
	expectedIDs := []string{"container1", "container2"}
	for _, id := range expectedIDs {
		createTestContainer(t, tmpDir, id, 1000)
	}

	docker := NewDockerInfoWithPath(tmpDir,"")
	ids, err := docker.GetContainerIDs()
	if err != nil {
		t.Fatalf("获取容器ID失败: %v", err)
	}

	// 验证返回的容器ID列表
	if len(ids) != len(expectedIDs) {
		t.Errorf("期望获得 %d 个容器ID, 实际获得 %d 个", len(expectedIDs), len(ids))
	}

	// 验证每个ID是否都在返回列表中
	for _, expectedID := range expectedIDs {
		found := false
		for _, id := range ids {
			if id == expectedID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("未找到期望的容器ID: %s", expectedID)
		}
	}
}

// 测试GetInitProcessPID方法
func TestGetInitProcessPID(t *testing.T) {
	tmpDir, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// 创建测试用例
	tests := []struct {
		name        string
		containerID string
		initPID     int
		wantErr    error
	}{
		{
			name:        "正常情况",
			containerID: "container1",
			initPID:     1000,
			wantErr:     nil,
		},
		{
			name:        "容器不存在",
			containerID: "nonexistent",
			initPID:     0,
			wantErr:     ErrReadFile,
		},
	}

	docker := NewDockerInfoWithPath(tmpDir,"")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.initPID > 0 {
				createTestContainer(t, tmpDir, tt.containerID, tt.initPID)
			}

			pid, err := docker.GetInitProcessPID(tt.containerID)
			if tt.wantErr != nil {
				if err == nil || !errors.Is(err, tt.wantErr) {
					t.Errorf("期望错误 %v, 得到 %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("未预期的错误: %v", err)
			}

			if pid != strconv.Itoa(tt.initPID) {
				t.Errorf("期望PID %d, 得到 %s", tt.initPID, pid)
			}
		})
	}
}

// 测试GetContainerInfo方法
func TestGetContainerInfo(t *testing.T) {
	tmpDir, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// 创建测试容器
	containerID := "test-container"
	initPID := 1000
	createTestContainer(t, tmpDir, containerID, initPID)

	docker := NewDockerInfoWithPath(tmpDir,"")
	info, err := docker.GetContainerInfo(containerID)
	if err != nil {
		t.Fatalf("获取容器信息失败: %v", err)
	}

	// 验证返回的容器信息
	if info.ID != containerID {
		t.Errorf("期望容器ID %s, 得到 %s", containerID, info.ID)
	}

	if info.InitPID != strconv.Itoa(initPID) {
		t.Errorf("期望初始进程ID %d, 得到 %s", initPID, info.InitPID)
	}
}

// 测试GetAllContainersInfo方法
func TestGetAllContainersInfo(t *testing.T) {
	tmpDir, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// 创建多个测试容器
	containers := []struct {
		id      string
		initPID int
	}{
		{"container1", 1000},
		{"container2", 2000},
	}

	for _, c := range containers {
		createTestContainer(t, tmpDir, c.id, c.initPID)
	}

	docker := NewDockerInfoWithPath(tmpDir,"")
	infos, err := docker.GetAllContainersInfo()
	if err != nil {
		t.Fatalf("获取所有容器信息失败: %v", err)
	}

	// 验证返回的容器数量
	if len(infos) != len(containers) {
		t.Errorf("期望 %d 个容器信息, 得到 %d 个", len(containers), len(infos))
	}

	// 验证每个容器的信息
	for _, c := range containers {
		found := false
		for _, info := range infos {
			if info.ID == c.id {
				found = true
				if info.InitPID != strconv.Itoa(c.initPID) {
					t.Errorf("容器 %s: 期望初始进程ID %d, 得到 %s", c.id, c.initPID, info.InitPID)
				}
				break
			}
		}
		if !found {
			t.Errorf("未找到容器 %s 的信息", c.id)
		}
	}
}