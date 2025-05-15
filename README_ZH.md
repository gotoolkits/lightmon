# lightmon

lightmon 是一款基于eBPF技术轻量级、Docker/K8s容器感知的网络流量监控工具。它能够实时捕获并分析主机及容器应用程序建立的网络连接，提供多种格式的监控数据输出，适用于系统监控、安全审计和网络故障排查等场景。

## DeepWiki Docs
点击查看 [DeepWiki Docs](https://deepwiki.com/gotoolkits/lightmon) 文档

## 架构概述

```
+---------------------+
|   用户空间程序       |
|  (Go语言实现)        |
+----------+----------+
           |
           | 通过perf buffer
           |
+----------v----------+
|   eBPF程序          |
|  (C语言实现)         |
|   - 跟踪系统调用     |
|   - 过滤网络事件     |
+---------------------+
```

## 功能特点

- **轻量高效**：基于eBPF技术，极低性能开销
- **全面监控**：跟踪TCP连接信息
- **容器感知**：自动识别K8s/Docker容器环境
- **进程感知**：自动识别流量关联进程及程序位置信息
- **灵活过滤**：支持多条件组合过滤规则
- **多格式输出**：支持日志文件、JSON、表格等多种输出格式

## 安装指南

### 依赖环境

```sh
# 基础依赖
sudo apt update
sudo apt install -y llvm clang

# Go环境 (建议1.23+)
```

### 编译安装

```sh
git clone https://github.com/gotoolkits/lightmon.git
cd lightmon

go mod tidy
make build
```

## 使用说明

### 基本使用

```sh
# 使用默认配置运行
./lightmon

# 指定配置文件
./lightmon -c config.yaml
```

### 输出格式

lightmon 支持多种输出格式 '-f'：

1. **LOG文本格式** (默认)
   ```
   [容器名称] [目标IP] [目标端口] [协议] [日志级别] [日志消息] [PID] [进程参数] [进程名] [源IP] [源端口] [时间] [用户名]
   {"conatiner":"dreamy_carson","dip":"183.2.172.17","dport":"65535","ipv6":0,"level":"info","msg":"","pid":"501750","procArgs":"www.baidu.com","procPath":"/usr/bin/busybox","sip":"10.1.8.14","sport":"7825","time":"2025-04-17T14:01:48+08:00","user":"root"}
   ```

2. **JSON格式** (使用 `-output json`)
   ```json
   {
     "kernelTime": "13898485459656",
     "goTime":"2025-04-17T14:09:49.162027869+08:00",
     "pid": 1234,
     "comm": "nginx",
     "addressFamily": "AF_INET",
     "saddr": "192.168.1.100",
     "sport": 34567,
     "daddr": "10.0.0.1", 
     "dport": 80,
     "container":"web-server",
   }
   ```

3. **表格格式** (使用 `-output table`)
   ```
   +----------+-------+-------+------+-----------------+-----------------+--------------+------------------------+
   | TIME     | USER  | PID   | AF   |  SRC            | DEST            | CONTAINER    |     PROCESS            |
   +----------+-------+-------+------+-----------------+-----------------+---------------------------------------+
   | 14:05:56 | root  | 1234  | v4   | 10.4.0.16:3425  | 10.0.0.1:80     | web-server   | /usr/local/bin/python  |
   +----------+-------+-------+------+-----------------+-----------------+---------------------------------------+
   ```

### 过滤功能

通过 `-exclude` 参数可以排除不需要监控的连接：

```sh
# 排除特定端口的流量
./lightmon -exclude 'dport=80'

# 排除特定IP范围的流量
./lightmon -exclude 'dip="192.168.1.0/24"'

# 组合条件过滤
./lightmon -exclude 'dport=80;dip="192.168.1.1";keyword="nginx"'
```

#### 过滤语法

- **基本条件**:
  - `dport=端口号` - 目标端口过滤
  - `dip='IP/CIDR'` - 目标IP过滤
  - `keyword='字符串'` - 进程路径与名称过滤
  - `container='字符串'` - 容器名称过滤

- **逻辑运算符**:
  - `&&` - AND逻辑
  - `||` - OR逻辑 
  - `;` - 条件组分隔符

#### 过滤示例

1. 排除本地网络和DNS流量:
   ```sh
   ./lightmon -exclude 'dip="192.168.1.0/24";dport=53'
   ```

2. 排除特定服务的监控:
   ```sh
   ./lightmon -exclude 'keyword="nginx";keyword="mysql"'
   ```

3. 复杂条件组合:
    ```sh
    ./lightmon -exclude 'dip="10.0.0.1" && dport=80; dip="10.0.0.1" && dport=443'
    ```

4. 排除特定容器名称“关键词”的流量:
    ```sh
    ./lightmon -exclude 'container="nginx";container="redis"'
    ```

## 开发指南

### 代码结构

```
lightmon/
├── conv/          # 协议转换
├── dockerinfo/    # 容器信息处理
├── event/         # 事件类型定义
├── filter/        # 过滤逻辑
├── headers/       # eBPF头文件
├── linux/         # Linux特定功能
├── outputer/      # 输出处理器
├── fentryTcpConnectSrc.c  # Fentry eBPF
├── sysEnterConnectSrc.c  # Tracepoint eBPF
└── main.go        # 程序入口
``` 

### 构建测试

```sh
# 运行单元测试
go test ./...

# 构建二进制
make build

# 清理构建
make clean
```

## 贡献

欢迎提交Issue和PR，贡献流程遵循标准GitHub流程。

## 许可证

Apache License 2.0，详见LICENSE.txt文件。
