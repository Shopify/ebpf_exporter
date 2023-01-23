package decoder

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/util"
)

// ContainerD is a decoder that transforms pid into Pod labels
type ContainerD struct {
	cache map[uint64][]byte
}

// Decode transforms pid in Pod labels
func (c *ContainerD) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	if c.cache == nil {
		c.cache = make(map[uint64][]byte)
	}

	byteOrder := util.GetHostByteOrder()
	pid := byteOrder.Uint64(in)

	if path, ok := c.cache[pid]; ok {
		return path, nil
	}

	if err := c.refreshCache(); err != nil {
		log.Printf("Error refreshing cgroup id to path map: %s", err)
	}

	if path, ok := c.cache[pid]; ok {
		return path, nil
	}

	return []byte(fmt.Sprintf("unknown_containerd_pid:%d", pid)), nil
}

func (c *ContainerD) refreshCache() error {
	pidPath := "/proc/*/cgroup"

	matches, err := filepath.Glob(pidPath)
	if err != nil {
		return err
	}

	for _, path := range matches {
		pid, err := strconv.Atoi(strings.Split(path, "/")[2])
		if err != nil {
			log.Printf("cannot extract pid from: %s", path)
			continue
		}
		cgroup, err := c.parseCgroupPath(path)
		if err != nil {
			log.Printf("[%s] %v", path, err)
			continue
		}
		c.cache[uint64(pid)] = []byte(cgroup)
	}

	return nil
}

func (c *ContainerD) parseCgroupPath(filename string) (string, error) {
	const cgroupPathPrefix = "1:name=systemd:"

	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		row := scanner.Text()
		if strings.HasPrefix(row, cgroupPathPrefix) {
			return strings.TrimPrefix(row, cgroupPathPrefix), nil
		}
	}
	return "", fmt.Errorf("could not extract cgroup")
}
