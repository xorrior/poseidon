package inject

import "github.com/xorrior/poseidon/pkg/utils/structs"

type Injection interface {
	TargetPid() int
	Shellcode() []byte
}

func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	tMsg := structs.ThreadMsg{}
	tMsg.TaskItem = task

}
