package getenv

import (
	"os"
	"strings"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

//Run - Function that executes the shell command
func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	tMsg := structs.ThreadMsg{}
	tMsg.TaskItem = task
	tMsg.Error = false
	tMsg.TaskResult = []byte(strings.Join(os.Environ(), "\n"))
	threadChannel <- tMsg
}
