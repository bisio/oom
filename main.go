package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/inancgumus/screen"
)

var memoryInfo map[string]int

var spaces *regexp.Regexp

var currentUID int

var threshold *int

var ignoreAdj *bool

var prefer *string

type processInfo struct {
	name    string
	memory  int
	badness int
	pid     int
}

var processes []processInfo

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func readValue(procID string, filename string, label string, field int, sep byte) string {
	f, e := os.Open("/proc/" + procID + "/" + filename)
	check(e)
	reader := bufio.NewReader(f)
	var line string
	for {
		line, _ = reader.ReadString(sep)
		if strings.HasPrefix(line, label) {
			break
		}
	}
	f.Close()
	pieces := strings.Fields(line)
	return pieces[field]
}

func inspectProcesses() {
	processes = processes[0:0]
	entries, _ := ioutil.ReadDir("/proc")
	for _, entry := range entries {
		isProcess, _ := regexp.MatchString(`\d+`, entry.Name())
		if entry.IsDir() && isProcess && isOurProcess(entry) {
			processes = append(processes, readProcessInfo(entry))
		}
	}
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].badness > processes[j].badness
	})

	// for i := 0; i < 5; i++ {
	// 	fmt.Printf("%s  %d  %d\n", processes[i].name, processes[i].badness, processes[i].memory)
	// }
}

func printMemory() {
	pctMemFree := float64(memoryInfo["MemAvailable"]) / float64(memoryInfo["MemTotal"]) * 100
	pctSwapFree := float64(memoryInfo["SwapFree"]) / float64(memoryInfo["SwapTotal"]) * 100
	t := time.Now()
	fmt.Printf("%s mem avail: %d of %d Mib (%2.0f %%), swap free: %d of %d Mib (%2.0f %%) \n",
		t.Format("15:04:05"),
		memoryInfo["MemAvailable"]/1000,
		memoryInfo["MemTotal"]/1000,
		pctMemFree,
		memoryInfo["SwapFree"]/1000,
		memoryInfo["SwapTotal"]/1000,
		pctSwapFree)
}

func updateMemory() {
	f, e := os.Open("/proc/meminfo")
	check(e)
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		pieces := strings.Fields(line)
		size, _ := strconv.Atoi(pieces[1])
		memoryInfo[pieces[0][:len(pieces[0])-1]] = size
	}
	f.Close()
}

func isOurProcess(procEntry os.FileInfo) bool {
	uid, _ := strconv.Atoi(readValue(procEntry.Name(), "status", "Uid", 1, '\n'))
	if uid == currentUID {
		return true
	}
	return false
}

func readProcessInfo(procEntry os.FileInfo) processInfo {
	var info processInfo
	memory, _ := strconv.Atoi(readValue(procEntry.Name(), "status", "VmRSS", 1, '\n'))
	info.memory = memory
	badness, _ := strconv.Atoi(readValue(procEntry.Name(), "oom_score", "", 0, '\n'))
	if *ignoreAdj {
		oomAdj, _ := strconv.Atoi(readValue(procEntry.Name(), "oom_score_adj", "", 0, '\n'))
		if oomAdj > 0 {
			badness -= oomAdj
		}
	}
	info.badness = badness
	name := readValue(procEntry.Name(), "cmdline", "", 0, 0)
	info.name = strings.ReplaceAll(name, "\x00", "")
	info.pid, _ = strconv.Atoi(procEntry.Name())
	return info
}

func killAndNotify(process processInfo) {
	syscall.Kill(process.pid, 9)
	message := fmt.Sprintf("killed process %s with pid %d", process.name, process.pid)
	fmt.Printf("%s\n", message)
	cmd := exec.Command("notify-send", "-u", "critical", "-i", "dialog-warning", "OOM", message)
	cmd.Run()

}

func checkAndAct() {
	pctMemFree := float64(memoryInfo["MemAvailable"]) / float64(memoryInfo["MemTotal"]) * 100
	if int(pctMemFree) < *threshold {
		fmt.Printf("ready to kill!\n")
		inspectProcesses()
		if *prefer != "" {
			fmt.Printf("trying to kill preferred\n")
			for _, process := range processes {
				if strings.Index(process.name, *prefer) != -1 {
					fmt.Printf("found process %s with pid  %d\n", process.name, process.pid)
					killAndNotify(process)
					return
				}

			}
			fmt.Printf("preferred not found\n")
		}
		fmt.Printf("going for the first of list\n")
		fmt.Printf("process %s with pid %d", processes[0].name, processes[0].pid)
		killAndNotify(processes[0])
	}

}

func main() {

	memoryInfo = make(map[string]int)
	processes = make([]processInfo, 0, 100)
	currentUser, _ := user.Current()
	uid, _ := strconv.Atoi(currentUser.Uid)
	currentUID = uid
	spaces = regexp.MustCompile(`\s+`)
	ignoreAdj = flag.Bool("i", false, "ignore oom_adj")
	threshold = flag.Int("t", 0, "available memory threshold in pct")
	prefer = flag.String("p", "", "Preferred process name to kill")

	flag.Parse()
	for {
		screen.Clear()
		screen.MoveTopLeft()

		updateMemory()
		printMemory()
		checkAndAct()

		time.Sleep(2 * time.Second)
	}
}
