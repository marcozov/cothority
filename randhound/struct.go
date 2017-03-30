package randhound

import (
	"sync"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/share"
	"github.com/dedis/crypto/share/pvss"
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
)

func init() {
	types := []interface{}{
		I1{}, R1{},
		I2{}, R2{},
		I3{}, R3{},
		WI1{}, WR1{},
		WI2{}, WR2{},
		WI3{}, WR3{},
	}
	for _, p := range types {
		network.RegisterMessage(p)
	}
}

// RandHound is the main protocol struct and implements the
// onet.ProtocolInstance interface.
type RandHound struct {
	*onet.TreeNodeInstance                         // ...
	mutex                  sync.Mutex              // ...
	nodes                  int                     // Total number of nodes (client + servers)
	groups                 int                     // Number of groups
	purpose                string                  // Purpose of protocol run
	time                   time.Time               // Timestamp of initiation
	seed                   []byte                  // Client-chosen seed for sharding
	sid                    []byte                  // Session identifier
	servers                [][]*onet.TreeNode      // Grouped servers
	keys                   [][]abstract.Point      // Grouped keys
	indices                [][]int                 // Grouped indices
	thresholds             []int                   // Groupd thresholds
	serverIdxToGroupNum    map[int]int             // Mapping of global server index to group number
	serverIdxToGroupIdx    map[int]int             // Mapping of global server index to group server index
	records                map[int]map[int]*Record // Buffer for shares; format: [source][target]*Record
	chosenSecrets          map[int][]int           // Chosen secrets contributing to collective randomness
	i1s                    map[int]*I1             // I1 messages sent to servers (index: group)
	i2s                    map[int]*I2             // I2 messages sent to servers (index: server)
	i3s                    map[int]*I3             // R1 messages received from servers (index: server)
	r1s                    map[int]*R1             // R2 messages received from servers (index: server)
	r2s                    map[int]*R2             // TODO
	r3s                    map[int]*R3             // TODO
	Done                   chan bool               // Channel to signal the end of a protocol run
	SecretReady            bool                    // Boolean to indicate whether the collect randomness is ready or not
}

// Record ...
type Record struct {
	Key      abstract.Point    // Public server key
	Eval     *share.PubShare   // Public commitment share of the commitment polynomial
	EncShare *pvss.PubVerShare // Encrypted verifiable share
	DecShare *pvss.PubVerShare // Decrypted verifiable share
}

// Share contains information on public verifiable shares and the source and
// target servers.
type Share struct {
	Source      int               // Source roster index
	Target      int               // Target roster index
	PubVerShare *pvss.PubVerShare // Public verifiable share
}

// Transcript represents the record of a protocol run created by the client.
type Transcript struct {
	SID           []byte             // Session identifier
	Nodes         int                // Total number of nodes (client + server)
	Purpose       string             // Purpose of protocol run
	Time          time.Time          // Timestamp of initiation
	Seed          []byte             // Client-chosen seed for sharding
	Client        abstract.Point     // Client public key
	Groups        [][]int            // Grouped server indices
	Keys          [][]abstract.Point // Grouped server public keys
	Thresholds    []int              // Grouped secret sharing thresholds
	ChosenSecrets map[int][]int      // Chosen secrets that contribute to collective randomness
	I1s           map[int]*I1        // I1 messages sent to servers
	I2s           map[int]*I2        // I2 messages sent to servers
	R1s           map[int]*R1        // R1 messages received from servers
	R2s           map[int]*R2        // R2 messages received from servers
}

// I1 is the message sent by the client to the servers in step 1.
type I1 struct {
	Sig       []byte   // Schnorr signature
	SID       []byte   // Session identifier
	Group     []uint32 // Group indices
	Threshold int      // Secret sharing threshold
}

// R1 is the reply sent by the servers to the client in step 2.
type R1 struct {
	Sig       []byte           // Schnorr signature
	HI1       []byte           // Hash of I1
	EncShares []*Share         // Encrypted shares
	Commit    []abstract.Point // Commitments to polynomial coefficients
}

// I2 is the message sent by the client to the servers in step 3.
type I2 struct {
	Sig           []byte            // Schnorr signature
	SID           []byte            // Session identifier
	ChosenSecrets []uint32          // Chosen secrets (flattened)
	EncShares     []*Share          // Encrypted shares
	Evals         []*share.PubShare // Commitments of polynomial evaluations
}

// R2 is the reply sent by the servers to the client in step 4.
type R2 struct {
	Sig       []byte   // Schnorr signature
	HI2       []byte   // Hash of I2
	DecShares []*Share // Decrypted shares
}

// I3 is the message sent by the client to the servers in step 5.
type I3 struct {
}

// R3 is the reply sent by the servers to the client in step 6.
type R3 struct {
}

// WI1 is a onet-wrapper around I1.
type WI1 struct {
	*onet.TreeNode
	I1
}

// WR1 is a onet-wrapper around R1.
type WR1 struct {
	*onet.TreeNode
	R1
}

// WI2 is a onet-wrapper around I2.
type WI2 struct {
	*onet.TreeNode
	I2
}

// WR2 is a onet-wrapper around R2.
type WR2 struct {
	*onet.TreeNode
	R2
}

// WI3 is a onet-wrapper around I3.
type WI3 struct {
	*onet.TreeNode
	I3
}

// WR3 is a onet-wrapper around R3.
type WR3 struct {
	*onet.TreeNode
	R3
}
