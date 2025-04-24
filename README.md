# lightmon

lightmon is a lightweight, Docker/K8s container-aware network traffic monitoring tool based on eBPF technology. It can capture and analyze network connections established by host and container applications in real-time, providing monitoring data in multiple formats. Suitable for system monitoring, security auditing, and network troubleshooting scenarios.

## Architecture Overview

```
+---------------------+
|   User-space Program |
|  (Implemented in Go) |
+----------+----------+
           |
           | via perf buffer
           |
+----------v----------+
|   eBPF Program      |
|  (Implemented in C) |
|   - Trace syscalls  |
|   - Filter network events |
+---------------------+
```

## Features

- **Lightweight & Efficient**: Based on eBPF technology with minimal performance overhead
- **Comprehensive Monitoring**: Tracks TCP connection information
- **Container-Aware**: Automatically identifies K8s/Docker container environments
- **Process-Aware**: Automatically identifies processes associated with traffic and their executable paths
- **Flexible Filtering**: Supports multi-condition combined filtering rules
- **Multiple Output Formats**: Supports log files, JSON, tables and other output formats

## Installation Guide

### Dependencies

```sh
# Basic dependencies
sudo apt update
sudo apt install -y llvm16 clang16

# Go environment (recommended 1.23+)
```

### Build & Install

```sh
git clone https://github.com/gotoolkits/lightmon.git
cd lightmon

go mod tidy
make build
```

## Usage

### Basic Usage

```sh
# Run with default configuration
./lightmon

# Specify config file
./lightmon -c config.yaml
```

### Output Formats

lightmon supports multiple output formats ('-f'):

1. **LOG format** (default)
   ```
   [container] [dest IP] [dest port] [protocol] [level] [message] [PID] [process args] [process name] [time] [user]
   {"conatiner":"dreamy_carson","dip":"183.2.172.17","dport":"65535","ipv6":0,"level":"info","msg":"","pid":"501750","procArgs":"www.baidu.com","procPath":"/usr/bin/busybox","time":"2025-04-17T14:01:48+08:00","user":"root"}
   ```

2. **JSON format** (use `-output json`)
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

3. **Table format** (use `-output table`)
   ```
   +---------------------+-------+--------+-------+-----------------+------------------------+
   | TIME     | USER  | PID   | AF    | DESTINATION  | CONTAINER    |     PROCESS            |
   +---------------------+-------+--------+-------+-----------------+------------------------+
   | 14:05:56 | root  | 1234  | ipv4  | 10.0.0.1:80  | web-server   | /usr/local/bin/python  |
   +---------------------+-------+--------+-------+-----------------+------------------------+
   ```

### Filtering

Use `-exclude` parameter to exclude unwanted connections:

```sh
# Exclude traffic to specific ports
./lightmon -exclude 'dport=80'

# Exclude traffic to specific IP ranges
./lightmon -exclude 'dip="192.168.1.0/24"'

# Combined conditions
./lightmon -exclude 'dport=80;dip="192.168.1.1";keyword="nginx"'
```

#### Filter Syntax

- **Basic conditions**:
  - `dport=port` - Filter by destination port
  - `dip='IP/CIDR'` - Filter by destination IP
  - `keyword='string'` - Filter by process path/name
  - `container='string'` - Filter by container name

- **Logical operators**:
  - `&&` - AND logic
  - `||` - OR logic
  - `;` - Condition group separator

#### Filter Examples

1. Exclude local network and DNS traffic:
   ```sh
   ./lightmon -exclude 'dip="192.168.1.0/24";dport=53'
   ```

2. Exclude specific services:
   ```sh
   ./lightmon -exclude 'keyword="nginx";keyword="mysql"'
   ```

3. Complex condition combinations:
   ```sh
   ./lightmon -exclude 'dip="10.0.0.1" && dport=80; dip="10.0.0.1" && dport=443'
   ```

4. Exclude traffic from containers with specific names:
   ```sh
   ./lightmon -exclude 'container="nginx";container="redis"'
   ```

## Development Guide

### Code Structure

```
lightmon/
├── conv/          # Protocol conversion
├── dockerinfo/    # Container info processing
├── event/         # Event type definitions
├── filter/        # Filtering logic
├── headers/       # eBPF headers
├── linux/         # Linux-specific functions
├── outputer/      # Output handlers
├── sysEnterConnectSrc.c  # Main eBPF program
└── main.go        # Program entry
```

### Build & Test

```sh
# Run unit tests
go test ./...

# Build binary
make build

# Clean build
make clean
```

## Contributing

Issues and PRs are welcome. Contribution process follows standard GitHub workflow.

## License

Apache License 2.0, see LICENSE.txt file for details.