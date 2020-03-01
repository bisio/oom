package main

import (
	"bufio"
	"errors"
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

func readValue(procID string, filename string, label string, field int, sep byte) (string, error) {
	f, e := os.Open("/proc/" + procID + "/" + filename)
	if e != nil {
		errMessage := fmt.Sprintf("Process %s has gone away", procID)
		return "", errors.New(errMessage)
	}

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
	return pieces[field], nil
}

func inspectProcesses() {
	processes = processes[0:0]
	entries, _ := ioutil.ReadDir("/proc")
	for _, entry := range entries {
		isProcess, _ := regexp.MatchString(`\d+`, entry.Name())
		ourProcess, err := isOurProcess(entry)

		if err != nil {
			continue
		}

		if entry.IsDir() && isProcess && ourProcess {
			processInfo, processInfoErr := readProcessInfo(entry)
			if processInfoErr != nil {
				continue
			}
			processes = append(processes, processInfo)
		}
	}
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].badness > processes[j].badness
	})

}

func dumpHogs() {
	for i := 0; i < 5; i++ {
		fmt.Printf("%s  %d  %d\n", processes[i].name, processes[i].badness, processes[i].memory)
	}
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

func isOurProcess(procEntry os.FileInfo) (bool, error) {
	value, err := readValue(procEntry.Name(), "status", "Uid", 1, '\n')

	if err != nil {
		return false, errors.New("Process has gone away")
	}

	uid, _ := strconv.Atoi(value)
	if uid == currentUID {
		return true, nil
	}
	return false, nil
}

func readProcessInfo(procEntry os.FileInfo) (processInfo, error) {
	var info processInfo
	memoryAsString, memoryErr := readValue(procEntry.Name(), "status", "VmRSS", 1, '\n')

	if memoryErr != nil {
		return processInfo{}, errors.New("Process has gone away")
	}

	memory, _ := strconv.Atoi(memoryAsString)
	info.memory = memory
	badnessAsString, badnessErr := readValue(procEntry.Name(), "oom_score", "", 0, '\n')

	if badnessErr != nil {
		return processInfo{}, errors.New("Process has gone away")
	}

	badness, _ := strconv.Atoi(badnessAsString)
	if *ignoreAdj {
		oomAdjAsString, oomAdjErr := readValue(procEntry.Name(), "oom_score_adj", "", 0, '\n')

		if oomAdjErr != nil {
			return processInfo{}, errors.New("Process has gone away")
		}

		oomAdj, _ := strconv.Atoi(oomAdjAsString)
		if oomAdj > 0 {
			badness -= oomAdj
		}
	}
	info.badness = badness

	name, nameErr := readValue(procEntry.Name(), "cmdline", "", 0, 0)

	if nameErr != nil {
		return processInfo{}, errors.New("Process has gone away")
	}

	info.name = strings.ReplaceAll(name, "\x00", "")
	info.pid, _ = strconv.Atoi(procEntry.Name())

	return info, nil
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
