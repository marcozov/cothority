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
	*onet.TreeNodeInstance                           // ...
	mutex                  sync.Mutex                // ...
	nodes                  int                       // Total number of nodes (client + servers)
	purpose                string                    // Purpose of protocol run
	time                   time.Time                 // Timestamp of initiation
	seed                   []byte                    // Client-chosen seed for sharding
	sid                    []byte                    // Session identifier
	groups                 []*Group                  // Group information
	serverIdxToGroupNum    map[int]int               // Mapping of global server index to group number
	serverIdxToGroupIdx    map[int]int               // Mapping of global server index to group server index
	i1s                    map[int]*I1               // ...
	i2s                    map[int]*I2               // ...
	i3s                    map[int]*I3               // ...
	r1s                    map[int]*R1               // ...
	r2s                    map[int]*R2               // ...
	r3s                    map[int]*R3               // ...
	evalCommit             map[int][]*share.PubShare // ...
	secret                 map[int][]int             // ...
	chosenSecret           map[int][]int             // ...
	Done                   chan bool                 // ...
	SecretReady            bool                      // ...
	records                map[int][]*Record         // ...
}

// Record ...
type Record struct {
	Key      abstract.Point    // ...
	EncShare *pvss.PubVerShare // ...
	DecShare *pvss.PubVerShare // ...
}

// Group ...
type Group struct {
	server    []*onet.TreeNode // List of servers
	key       []abstract.Point // Public keys of the servers
	index     []int            // Roster indices of servers
	threshold int              // Secret sharding threshold
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
	Sig      []byte           // Schnorr signature
	HI1      []byte           // Hash of I1
	EncShare []*Share         // Encrypted shares
	Commit   []abstract.Point // Commitments to polynomial coefficients
}

// I2 is the message sent by the client to the servers in step 3.
type I2 struct {
	Sig          []byte            // Schnorr signature
	SID          []byte            // Session identifier
	ChosenSecret []uint32          // Chosen secrets (flattened)
	EncShare     []*Share          // Encrypted shares
	EvalCommit   []*share.PubShare // Commitments to polynomial coefficients
}

// R2 is the reply sent by the servers to the client in step 4.
type R2 struct {
	Sig      []byte   // Schnorr signature
	HI2      []byte   // Hash of I2
	DecShare []*Share // Decrypted shares
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
