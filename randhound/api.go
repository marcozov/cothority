package randhound

import (
	"errors"
	"fmt"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cosi"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/share/pvss"
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

// Setup initializes a RandHound instance on client-side and sets some basic
// parameters. Needs to be called before Start.
func (rh *RandHound) Setup(nodes int, groups int, purpose string) error {

	var err error

	// Setup session
	if rh.Session, err = rh.newSession(nodes, groups, purpose, time.Time{}, nil, rh.Public()); err != nil {
		return err
	}

	// Setup CoSi instance
	rh.CoSi = cosi.NewCosi(rh.Suite(), rh.Private(), rh.Roster().Publics())

	rh.records = make(map[int]map[int]*Record)
	rh.chosenSecrets = make(map[int][]int)
	rh.i2s = make(map[int]*I2)
	rh.r1s = make(map[int]*R1)
	rh.r2s = make(map[int]*R2)
	rh.r3s = make(map[int]*R3)
	rh.Done = make(chan bool, 1)
	rh.SecretReady = false

	return nil
}

// Start initiates the RandHound protocol run. The client pseudorandomly
// chooses the server grouping, forms an I1 message for each group, and sends
// it to all servers of that group.
func (rh *RandHound) Start() error {

	rh.mutex.Lock()
	defer rh.mutex.Unlock()

	// Setup first message
	rh.i1 = &I1{
		SID:     rh.sid,
		Groups:  rh.groups,
		Seed:    rh.seed,
		Purpose: rh.purpose,
		Time:    rh.time,
	}

	// Sign first message
	if err := signSchnorr(rh.Suite(), rh.Private(), rh.i1); err != nil {
		return err
	}

	// Broadcast message to servers which process it as shown in handleI1(...).
	if err := rh.Broadcast(rh.i1); err != nil {
		return err
	}

	return nil
}

// TODO: make sharding independent of TreeNodes (use only indices); then it can
// be used to validate the transcript

// Shard produces a pseudorandom sharding of the network entity list
// based on a seed and a number of requested shards.
func (rh *RandHound) Shard(nodes []*onet.TreeNode, seed []byte, shards int) ([][]*onet.TreeNode, error) {
	if len(nodes) == 0 || shards == 0 || len(nodes) < shards {
		return nil, fmt.Errorf("number of requested shards not supported")
	}

	// Compute a random permutation of [1,n-1]
	// TODO: other nodes than the one at index 0 can start a RandHound round!
	prng := rh.Suite().Cipher(seed)
	m := make([]int, len(nodes)-1)
	for i := range m {
		j := int(random.Uint64(prng) % uint64(i+1))
		m[i] = m[j]
		m[j] = i + 1
	}

	// Create sharding of the current roster according to the above permutation
	sharding := make([][]*onet.TreeNode, shards) //*onet.TreeNode
	for i, j := range m {
		sharding[i%shards] = append(sharding[i%shards], nodes[j])
	}

	return sharding, nil
}

// Random creates the collective randomness from the shares and the protocol
// transcript.
func (rh *RandHound) Random() ([]byte, *Transcript, error) {
	rh.mutex.Lock()
	defer rh.mutex.Unlock()

	if !rh.SecretReady {
		return nil, nil, errors.New("secret not recoverable")
	}

	rnd := rh.Suite().Point().Null()

	// Unwrap the records
	var X []abstract.Point
	var encShares []*pvss.PubVerShare
	var decShares []*pvss.PubVerShare

	G := rh.Suite().Point().Base()
	for i, group := range rh.chosenSecrets {
		for _, src := range group {
			for _, r := range rh.records[src] {
				if r.Key != nil && r.EncShare != nil && r.DecShare != nil {
					X = append(X, r.Key)
					encShares = append(encShares, r.EncShare)
					decShares = append(decShares, r.DecShare)
				}
			}
			ps, err := pvss.RecoverSecret(rh.Suite(), G, X, encShares, decShares, rh.thresholds[i], len(rh.servers[i]))
			if err != nil {
				return nil, nil, err
			}
			rnd = rh.Suite().Point().Add(rnd, ps)
			X = make([]abstract.Point, 0)
			encShares = make([]*pvss.PubVerShare, 0)
			decShares = make([]*pvss.PubVerShare, 0)
		}
	}

	rb, err := rnd.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	transcript := &Transcript{
	//SID:           rh.sid,
	//Nodes:         rh.nodes,
	//Purpose:       rh.purpose,
	//Time:          rh.time,
	//Seed:          rh.seed,
	//Client:        rh.Public(),
	//Groups:        rh.indices,
	//Keys:          rh.keys,
	//Thresholds:    rh.thresholds,
	//ChosenSecrets: rh.chosenSecrets,
	//I1s:           rh.i1s,
	//I2s: rh.i2s,
	//R1s: rh.r1s,
	//R2s: rh.r2s,
	}

	return rb, transcript, nil
}

// TODO: verify
// (1) Session ID
// (2) Encrypted shares
// (3) Decrypted shares
// (4) Recovered randomness == presented randomness

// Verify checks a given collective random string against its protocol transcript.
//func (rh *RandHound) Verify(suite abstract.Suite, random []byte, t *Transcript) error {
//	rh.mutex.Lock()
//	defer rh.mutex.Unlock()
//
//	sid, err := rh.sessionID(t.Client, t.Keys, t.Groups, t.Purpose, t.Time)
//	if err != nil {
//		return err
//	}
//
//	if !bytes.Equal(t.SID, sid) {
//		return fmt.Errorf("Wrong session identifier")
//	}
//
//	// Verify I1 signatures
//	for _, i1 := range t.I1s {
//		if err := verifySchnorr(suite, t.Client, i1); err != nil {
//			return err
//		}
//	}
//
//	// Verify R1 signatures
//	for src, r1 := range t.R1s {
//		var key abstract.Point
//		for i := range t.Groups {
//			for j := range t.Groups[i] {
//				if src == t.Groups[i][j] {
//					key = t.Keys[i][j]
//				}
//			}
//		}
//		if err := verifySchnorr(suite, key, r1); err != nil {
//			return err
//		}
//	}
//
//	// Verify I2 signatures
//	for _, i2 := range t.I2s {
//		if err := verifySchnorr(suite, t.Client, i2); err != nil {
//			return err
//		}
//	}
//
//	// Verify R2 signatures
//	for src, r2 := range t.R2s {
//		var key abstract.Point
//		for i := range t.Groups {
//			for j := range t.Groups[i] {
//				if src == t.Groups[i][j] {
//					key = t.Keys[i][j]
//				}
//			}
//		}
//		if err := verifySchnorr(suite, key, r2); err != nil {
//			return err
//		}
//	}
//
//	// Verify message hashes HI1 and HI2; it is okay if some messages are
//	// missing as long as there are enough to reconstruct the chosen secrets
//	for i, msg := range t.I1s {
//		for _, j := range t.Groups[i] {
//			if _, ok := t.R1s[j]; ok {
//				if err := verifyMessage(suite, msg, t.R1s[j].HI1); err != nil {
//					return err
//				}
//			} else {
//				log.Lvlf2("Couldn't find R1 message of server %v", j)
//			}
//		}
//	}
//
//	for i, msg := range t.I2s {
//		if _, ok := t.R2s[i]; ok {
//			if err := verifyMessage(suite, msg, t.R2s[i].HI2); err != nil {
//				return err
//			}
//		} else {
//			log.Lvlf2("Couldn't find R2 message of server %v", i)
//		}
//	}
//
//	// Verify that all servers received the same client commitment
//	for server, msg := range t.I2s {
//		c := 0
//		// Deterministically iterate over map[int][]int
//		for i := 0; i < len(t.ChosenSecrets); i++ {
//			for _, cs := range t.ChosenSecrets[i] {
//				if int(msg.ChosenSecrets[c]) != cs {
//					return fmt.Errorf("Server %v received wrong client commitment", server)
//				}
//				c++
//			}
//		}
//	}
//
//	// Recover and verify the randomness
//	G := suite.Point().Base()
//	H, _ := suite.Point().Pick(nil, suite.Cipher(t.SID))
//	rnd := suite.Point().Null()
//	for i, group := range t.ChosenSecrets {
//		for _, src := range group {
//			var X []abstract.Point
//			var encShares []*pvss.PubVerShare
//			var decShares []*pvss.PubVerShare
//
//			// All R1 messages of the chosen secrets should be there
//			if _, ok := t.R1s[src]; !ok {
//				return errors.New("R1 message not found")
//			}
//			r1 := t.R1s[src]
//
//			// Check availability of corresponding R2 messages, skip if not there
//			for _, encShare := range r1.EncShares {
//				target := encShare.Target
//				if _, ok := t.R2s[target]; !ok {
//					continue
//				}
//				pubPoly := share.NewPubPoly(rh.Suite(), H, r1.Commit)
//				pos := encShare.PubVerShare.S.I
//				key := t.Keys[i][pos]
//				sH := pubPoly.Eval(pos).V
//				r2 := t.R2s[target]
//				for _, decShare := range r2.DecShares {
//					if decShare.Source == src {
//						if pvss.VerifyEncShare(suite, H, key, sH, encShare.PubVerShare) == nil {
//							if pvss.VerifyDecShare(suite, G, key, encShare.PubVerShare, decShare.PubVerShare) == nil {
//								X = append(X, key)
//								encShares = append(encShares, encShare.PubVerShare)
//								decShares = append(decShares, decShare.PubVerShare)
//							}
//						}
//					}
//				}
//			}
//
//			ps, err := pvss.RecoverSecret(rh.Suite(), G, X, encShares, decShares, t.Thresholds[i], len(t.Groups[i]))
//			if err != nil {
//				return err
//			}
//			rnd = rh.Suite().Point().Add(rnd, ps)
//		}
//	}
//
//	rb, err := rnd.MarshalBinary()
//	if err != nil {
//		return err
//	}
//
//	if !bytes.Equal(random, rb) {
//		return errors.New("bad randomness")
//	}
//
//	return nil
//}
