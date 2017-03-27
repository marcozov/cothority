package randhound

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/onet"
)

func init() {
	onet.GlobalProtocolRegister("RandHound", NewRandHound)
}

// NewRandHound generates a new RandHound instance.
func NewRandHound(node *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	rh := &RandHound{
		TreeNodeInstance: node,
	}
	h := []interface{}{
		rh.handleI1, rh.handleI2, rh.handleI3,
		rh.handleR1, rh.handleR2, rh.handleR3,
	}
	err := rh.RegisterHandlers(h...)
	return rh, err
}

// Setup configures a RandHound instance on client-side. Needs to be called
// before Start.
func (rh *RandHound) Setup(nodes int, faulty int, groups, purpose string) error {
	return nil
}

// Start initiates the RandHound protocol run. The client pseudo-randomly
// chooses the server grouping, forms an I1 message for each group, and sends
// it to all servers of that group.
func (rh *RandHound) Start() error {
	return nil
}

// Shard produces a pseudorandom sharding of the network entity list
// based on a seed and a number of requested shards.
func (rh *RandHound) Shard() ([][]*onet.Treenode, [][]abstract.Point, error) {
	return nil, nil, nil
}

// Random creates the collective randomness from the shares and the protocol
// transcript.
func (rh *RandHound) Random() ([]byte, *Transcript, error) {
	return nil, nil, nil
}

// Verify checks a given collective random string against its protocol transcript.
func (rh *RandHound) Verify() error {
	return nil
}

func (rh *RandHound) sessionID() ([]byte, error) {
	return nil, nil
}

func (rh *RandHound) handleI1(i1 WI1) error {

	return nil
}

func (rh *RandHound) handleR1(i1 WI1) error {

	return nil
}

func (rh *RandHound) handleI2(i1 WI1) error {

	return nil
}

func (rh *RandHound) handleR2(i1 WI1) error {

	return nil
}

func (rh *RandHound) handleI3(i1 WI1) error {

	return nil
}

func (rh *RandHound) handleR3(i1 WI1) error {
	return nil
}
