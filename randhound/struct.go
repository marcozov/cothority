package randhound

import (
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
	*onet.TreeNodeInstance
}

// Transcript represents the record of a protocol run created by the client.
type Transcript struct {
}

// I1 is the message sent by the client to the servers in step 1.
type I1 struct {
}

// R1 is the reply sent by the servers to the client in step 2.
type R1 struct {
}

// I2 is the message sent by the client to the servers in step 3.
type I2 struct {
}

// R2 is the reply sent by the servers to the client in step 4.
type R2 struct {
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
