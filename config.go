package main

import (
	"fmt"
	"github.com/containerd/cgroups"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/shirou/gopsutil/cpu"
	"os"
	"path/filepath"
	"runtime"
)

const (
	SCAN_DIR_HIERARCHY =5
	MAX_SCAN_SIZE = 10*10000
	MAX_CPU_USAGE = 0.7

)

func getNumCPU() int {
	//使用第三方模块获取CPU核心数量
	gopsutilCpu, err := cpu.Info()
	if err != nil {
		return runtime.NumCPU()

	}
	return len(gopsutilCpu)

}


var SKIP_SUFFIX = map[string]int{
	".svg":1,
	".woff":1,
	".woff2":1,
	".ttf":1,
	".ico":1,
	".jpg":1,
	".png":1,
	".jpeg":1,
	".gif":1,
	".bmp":1,
	".h":1,
	".inc":1,
	".o":1,
	".c":1,
	".cpp":1,
	".rs":1,
	".lock":1,
	".go":1,
	".md":1,
	".zip": 1,
	".rar": 1,
	".7z": 1,
	".tar": 1,
	".gz": 1,
	".bz2": 1,
	".iso": 1,
	".so": 1,
	".apk": 1,
	".ipa": 1,
	".deb": 1,
	".rpm": 1,
	".class": 1,
	".pyc": 1,
	".pyo": 1,
	".py": 1,
	".java": 1,
	".js": 1,
	".ts": 1,
	".css": 1,
	".html": 1,
	".htm": 1,
	".xml": 1,
	".json": 1,
	".csv": 1,
	".txt": 1,
	".doc": 1,
	".docx": 1,
	".ppt": 1,
	".pptx": 1,
	".xls": 1,
	".xlsx": 1,
	".pdf": 1,
	".mp3": 1,
	".mp4": 1,
	".log": 1,
	".db": 1,
	".sql": 1,
	".ini": 1,
	".conf": 1,
	".yaml": 1,
	".yml": 1,
}



var SCAN_DIR_FILTER = map[string]bool{
	"/root/.debug":          true,
	"/root/.vscode":         true,
	"/root/.bash_history":   true,
	"/usr/bin/killall":      true,
	"/usr/bin/virt":         true,
	"/usr/bin/upx":          true,
	"/usr/bin/fim":          true,
	"/usr/bin/nc":           true,
	"/usr/bin/inputattach":  true,
	"/usr/bin/clamdscan":    true,
	"/usr/bin/clamconf":     true,
	"/usr/bin/sigtool":      true,
	"/usr/bin/clamdtop":     true,
	"/usr/bin/clamsubmit":   true,
	"/usr/bin/clambc":       true,
	"/usr/bin/clamscan":     true,
	"/usr/sbin/clamd":       true,
	"/usr/sbin/clamonacc":   true,
	"/bin/nc":               true,
	"/bin/netcat":           true,
	"/bin/upx":              true,
	"/bin/inputattach":      true,
	"/etc/alternatives/upx": true,
	"/etc/alternatives/nc":  true,
	"/etc/alternatives/netcat": true,
	"/etc/dictionaries-common/words": true,
	"/dev":          true,
	"/boot":         true,
	"/sys":          true,
	"/usr/src":      true,
	"/usr/local/src": true,
	"/www/Recycle_bin": true,
	"/www/server":      true,
}


func createCgroupWithCPULimit(pid int, limit int) (cgroups.Cgroup, error) {
	// 使用默认的cgroup层次结构创建一个新的cgroup
	control, err := cgroups.New(cgroups.V1, cgroups.StaticPath(fmt.Sprintf("/cgroup_%d", pid)), &specs.LinuxResources{})
	if err != nil {
		return nil, fmt.Errorf("创建cgroup失败: %v", err)
	}
	//CPU数量
	cpuCount := getNumCPU()
	// 计算配额
	quota := int64(float64(cpuCount) * float64(limit) * 1000)

	// 设置CPU资源限制
	err = control.Update(&specs.LinuxResources{
		CPU: &specs.LinuxCPU{
			Quota:  &quota,
			Period: pointer(100000),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("设置CPU限制失败: %v", err)
	}
	// 将当前进程添加到cgroup
	err = control.Add(cgroups.Process{Pid: pid})
	if err != nil {
		return nil, fmt.Errorf("将进程添加到cgroup失败: %v", err)
	}

	return control, nil
}

func pointer(i uint64) *uint64 {
	return &i
}


func walk(CL_ENGINE_MAX_RECURSION int,path string, depth int, visit func(string, os.FileInfo, error) error) error {
	if depth > CL_ENGINE_MAX_RECURSION {
		return nil
	}
	return filepath.Walk(path, func(currentPath string, info os.FileInfo, err error) error {
		if info == nil {
			return err
		}

		if info.IsDir() {
			if _, ok := SCAN_DIR_FILTER[currentPath]; ok {
				return filepath.SkipDir
			}
			if currentPath != path {
				err = walk(CL_ENGINE_MAX_RECURSION,currentPath, depth+1, visit)
				return filepath.SkipDir
			}
		}

		if _, ok := SCAN_DIR_FILTER[currentPath]; ok {
			return nil
		}

		return visit(currentPath, info, err)
	})
}


