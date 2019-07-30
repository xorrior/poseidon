// +build linux

package keys

import (
	"encoding/base64"
	"log"

	"github.com/xorrior/keyctl"
)

//Keydetails - struct that holds information about a key
type Keydetails struct {
	Name        string            `json:"name"`
	ID          int32             `json:"id"`
	Permissions Permissiondetails `json:"permissions"`
	Keytype     string            `json:"keytype"`
	UID         int               `json:"uid"`
	Valid       bool              `json:"valid"`
	Data        string            `json:"string"`
}

//Permissiondetails - struct that holds permission details for a given key
type Permissiondetails struct {
	User    string `json:"user"`
	Process string `json:"process"`
	Other   string `json:"other"`
	Group   string `json:"group"`
}

//KeyContents - struct that represent raw key contents
type KeyContents struct {
}

//ListKeysForSession - List all of the keys for the current session
func ListKeysForSession() ([]Keydetails, error) {
	keyring, err := keyctl.SessionKeyring()

	if err != nil {
		log.Printf("Failed to get session keyring: %s", err.Error())
		return nil, err
	}

	keys, err := keyctl.ListKeyring(keyring)

	if err != nil {
		log.Printf("Unable to get key contents")
		return nil, err
	}

	res := make([]Keydetails, len(keys))

	for i, key := range keys {
		info, _ := key.Info()
		res[i].Name = info.Name
		res[i].ID = key.Id
		res[i].Keytype = info.Type
		res[i].UID = info.Uid
		res[i].Valid = info.Valid()
		res[i].Permissions.User = info.Perm.User()
		res[i].Permissions.Group = info.Perm.Group()
		res[i].Permissions.Process = info.Perm.Process()
		res[i].Permissions.Other = info.Perm.Other()

	}

	return res, nil
}

func Searchforkeywithtype(name string, typeName string) ([]Keydetails, error) {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		log.Printf("Failed to get session keyring: %s", err.Error())
		return nil, err
	}

	key, err := keyring.SearchWithType(name, typeName)
	if err != nil {
		return nil, err
	}

	res := make([]Keydetails, 1)
	info, _ := key.Info()
	raw, err := key.Get()

	res[0].Name = info.Name
	res[0].ID = key.Id()

	if err == nil {
		res[0].Data = base64.StdEncoding.EncodeToString(raw)
	}

	res[0].Keytype = info.Type
	res[0].UID = info.Uid
	res[0].Valid = info.Valid()
	res[0].Permissions.User = info.Perm.User()
	res[0].Permissions.Group = info.Perm.Group()
	res[0].Permissions.Process = info.Perm.Process()
	res[0].Permissions.Other = info.Perm.Other()

	return res, nil
}

func ListKeysForProcess() ([]Keydetails, error) {
	keyring, err := keyctl.ProcessKeyring()
	if err != nil {
		log.Printf("Failed to get session keyring: %s", err.Error())
		return nil, err
	}

	keys, err := keyctl.ListKeyring(keyring)

	if err != nil {
		log.Printf("Unable to get key contents")
		return nil, err
	}

	res := make([]Keydetails, len(keys))

	for i, key := range keys {
		info, _ := key.Info()
		res[i].Name = info.Name
		res[i].ID = key.Id
		res[i].Keytype = info.Type
		res[i].UID = info.Uid
		res[i].Valid = info.Valid()

		res[i].Permissions.User = info.Perm.User()
		res[i].Permissions.Group = info.Perm.Group()
		res[i].Permissions.Process = info.Perm.Process()
		res[i].Permissions.Other = info.Perm.Other()

	}

	return res, nil
}

//ListKeysForUserSession - List all of the keys private to the current user
func ListKeysForUserSession() ([]Keydetails, error) {
	keyring, err := keyctl.UserSessionKeyring()
	if err != nil {
		log.Printf("Failed to get session keyring: %s", err.Error())
		return nil, err
	}

	keys, err := keyctl.ListKeyring(keyring)

	if err != nil {
		log.Printf("Unable to get key contents")
		return nil, err
	}

	res := make([]Keydetails, len(keys))

	for i, key := range keys {
		info, _ := key.Info()
		res[i].Name = info.Name
		res[i].ID = key.Id
		res[i].Keytype = info.Type
		res[i].UID = info.Uid
		res[i].Valid = info.Valid()

		res[i].Permissions.User = info.Perm.User()
		res[i].Permissions.Group = info.Perm.Group()
		res[i].Permissions.Process = info.Perm.Process()
		res[i].Permissions.Other = info.Perm.Other()

	}

	return res, nil
}

func Searchcurrentsessionkeyring(name string) ([]Keydetails, error) {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return nil, err
	}

	key, err := keyring.Search(name)
	if err != nil {
		return nil, err
	}

	res := make([]Keydetails, 1)
	info, _ := key.Info()
	raw, err := key.Get()

	res[0].Name = info.Name
	res[0].ID = key.Id()

	if err == nil {
		res[0].Data = base64.StdEncoding.EncodeToString(raw)
	}

	res[0].Keytype = info.Type
	res[0].UID = info.Uid
	res[0].Valid = info.Valid()
	res[0].Permissions.User = info.Perm.User()
	res[0].Permissions.Group = info.Perm.Group()
	res[0].Permissions.Process = info.Perm.Process()
	res[0].Permissions.Other = info.Perm.Other()

	return res, nil
}
