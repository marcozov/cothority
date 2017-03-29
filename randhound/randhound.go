package randhound

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/hash"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/share"
	"github.com/dedis/crypto/share/pvss"
	"github.com/dedis/crypto/sign"
	"github.com/dedis/onet"
	"github.com/dedis/onet/crypto"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

// TODO: decide on singular or plural in slice names

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

// Setup initializes a RandHound instance on client-side. Needs to be called
// before Start.
func (rh *RandHound) Setup(nodes int, groups int, purpose string) error {
	rh.nodes = nodes
	rh.purpose = purpose
	rh.groups = make([]*Group, groups)
	rh.serverIdxToGroupNum = make(map[int]int)
	rh.serverIdxToGroupIdx = make(map[int]int)
	rh.i1s = make(map[int]*I1)
	rh.i2s = make(map[int]*I2)
	rh.i3s = make(map[int]*I3)
	rh.r1s = make(map[int]*R1)
	rh.r2s = make(map[int]*R2)
	rh.r3s = make(map[int]*R3)
	rh.evalCommit = make(map[int][]*share.PubShare)
	rh.secret = make(map[int][]int)
	rh.chosenSecret = make(map[int][]int)
	rh.Done = make(chan bool, 1)
	rh.SecretReady = false
	rh.records = make(map[int][]*Record)
	return nil
}

// Start initiates the RandHound protocol run. The client pseudorandomly
// chooses the server grouping, forms an I1 message for each group, and sends
// it to all servers of that group.
func (rh *RandHound) Start() error {
	var err error

	// Set timestamp
	rh.time = time.Now()

	// Choose sharding seed
	rh.seed = random.Bytes(rh.Suite().Hash().Size(), random.Stream)

	// Shard servers
	groups, keys, err := rh.Shard(rh.seed, len(rh.groups))
	if err != nil {
		return err
	}

	// Setup group information
	for i, grp := range groups {
		idx := make([]int, len(grp))
		for j, s := range grp {
			k := s.RosterIndex
			rh.serverIdxToGroupNum[k] = i
			rh.serverIdxToGroupIdx[k] = j
			idx[j] = k
		}
		rh.groups[i] = &Group{
			server:    grp,
			key:       keys[i],
			index:     idx,
			threshold: len(grp)/3 + 1,
		}
	}

	// Compute session identifier
	rh.sid, err = rh.sessionID(rh.Public(), rh.groups, rh.purpose, rh.time) // TODO: probably needs to change for verification later
	if err != nil {
		return err
	}

	// Multicast first message to grouped servers
	for i, group := range rh.groups {
		index := make([]uint32, len(group.server))
		for j, s := range group.server {
			index[j] = uint32(s.RosterIndex)
		}
		i1 := &I1{
			SID:       rh.sid,
			Group:     index,
			Threshold: group.threshold,
		}
		rh.mutex.Lock()
		if err := signSchnorr(rh.Suite(), rh.Private(), i1); err != nil {
			rh.mutex.Unlock()
			return err
		}
		rh.i1s[i] = i1
		rh.mutex.Unlock()
		if err := rh.Multicast(i1, group.server...); err != nil {
			return err
		}
	}
	return nil
}

// Shard produces a pseudorandom sharding of the network entity list
// based on a seed and a number of requested shards.
func (rh *RandHound) Shard(seed []byte, shards int) ([][]*onet.TreeNode, [][]abstract.Point, error) {
	if shards == 0 || rh.nodes < shards {
		return nil, nil, fmt.Errorf("Number of requested shards not supported")
	}

	// Compute a random permutation of [1,n-1]
	prng := rh.Suite().Cipher(seed)
	m := make([]int, rh.nodes-1)
	for i := range m {
		j := int(random.Uint64(prng) % uint64(i+1))
		m[i] = m[j]
		m[j] = i + 1
	}

	// Create sharding of the current roster according to the above permutation
	el := rh.List()
	sharding := make([][]*onet.TreeNode, shards)
	keys := make([][]abstract.Point, shards)
	for i, j := range m {
		sharding[i%shards] = append(sharding[i%shards], el[j])
		keys[i%shards] = append(keys[i%shards], el[j].ServerIdentity.Public)
	}

	return sharding, keys, nil
}

// Random creates the collective randomness from the shares and the protocol
// transcript.
func (rh *RandHound) Random() ([]byte, *Transcript, error) {

	rh.mutex.Lock()
	defer rh.mutex.Unlock()

	if !rh.SecretReady {
		return nil, nil, errors.New("secret not recoverable")
	}

	//H, _ := rh.Suite().Point().Pick(nil, rh.Suite().Cipher(rh.sid))
	rnd := rh.Suite().Point().Null()

	// Unwrap the records
	var X []abstract.Point
	var encShares []*pvss.PubVerShare
	var decShares []*pvss.PubVerShare
	for src, r := range rh.records {
		grp := rh.serverIdxToGroupNum[src]
		G := rh.Suite().Point().Base()
		for i := 0; i < len(r); i++ {
			X = append(X, r[i].Key)
			encShares = append(encShares, r[i].EncShare)
			decShares = append(decShares, r[i].DecShare)
		}
		ps, err := pvss.RecoverSecret(rh.Suite(), G, X, encShares, decShares, rh.groups[grp].threshold, len(rh.groups[grp].server))
		log.Lvl1(ps, src)
		if err != nil {
			return nil, nil, err
		}
		rnd = rh.Suite().Point().Add(rnd, ps)
		X = make([]abstract.Point, 0)
		encShares = make([]*pvss.PubVerShare, 0)
		decShares = make([]*pvss.PubVerShare, 0)
	}

	rb, err := rnd.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return rb, nil, nil
}

// Verify checks a given collective random string against its protocol transcript.
func (rh *RandHound) Verify() error {
	return nil
}

func (rh *RandHound) sessionID(clientKey abstract.Point, groups []*Group, purpose string, time time.Time) ([]byte, error) {

	keyBuf := new(bytes.Buffer)
	idxBuf := new(bytes.Buffer)
	miscBuf := new(bytes.Buffer)

	// Process client key
	cb, err := clientKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err := keyBuf.Write(cb); err != nil {
		return nil, err
	}

	// Process server keys and indices
	for _, grp := range groups {
		for _, server := range grp.server {
			sb, err := server.ServerIdentity.Public.MarshalBinary()
			if err != nil {
				return nil, err
			}
			if _, err := keyBuf.Write(sb); err != nil {
				return nil, err
			}
			if err := binary.Write(idxBuf, binary.LittleEndian, uint32(server.RosterIndex)); err != nil {
				return nil, err
			}
		}
	}

	// Process purpose string
	if _, err := miscBuf.WriteString(purpose); err != nil {
		return nil, err
	}

	// Process time stamp
	t, err := time.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if _, err := miscBuf.Write(t); err != nil {
		return nil, err
	}

	hash := rh.Suite().Hash()
	if _, err := io.Copy(hash, keyBuf); err != nil {
		return nil, err
	}
	if _, err := io.Copy(hash, idxBuf); err != nil {
		return nil, err
	}
	if _, err := io.Copy(hash, miscBuf); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func signSchnorr(suite abstract.Suite, key abstract.Scalar, m interface{}) error {

	// Reset signature field
	reflect.ValueOf(m).Elem().FieldByName("Sig").SetBytes([]byte{0}) // XXX: hack

	// Marshal message
	mb, err := network.Marshal(m) // TODO: change m to interface with hash to make it compatible to other languages (network.Marshal() adds struct-identifiers)
	if err != nil {
		return err
	}

	// Sign message
	sig, err := sign.Schnorr(suite, key, mb)
	if err != nil {
		return err
	}

	// Store signature
	reflect.ValueOf(m).Elem().FieldByName("Sig").SetBytes(sig) // XXX: hack

	return nil
}

func verifySchnorr(suite abstract.Suite, key abstract.Point, m interface{}) error {

	// Make a copy of the signature
	sig := reflect.ValueOf(m).Elem().FieldByName("Sig").Bytes()

	// Reset signature field
	reflect.ValueOf(m).Elem().FieldByName("Sig").SetBytes([]byte{0}) // XXX: hack

	// Marshal message
	mb, err := network.Marshal(m) // TODO: change m to interface with hash to make it compatible to other languages (network.Marshal() adds struct-identifiers)
	if err != nil {
		return err
	}

	// Copy back original signature
	reflect.ValueOf(m).Elem().FieldByName("Sig").SetBytes(sig) // XXX: hack

	return sign.VerifySchnorr(suite, key, mb, sig)
}

func verifyMessage(suite abstract.Suite, m interface{}, hash1 []byte) error {

	// Make a copy of the signature
	sig := reflect.ValueOf(m).Elem().FieldByName("Sig").Bytes()

	// Reset signature field
	reflect.ValueOf(m).Elem().FieldByName("Sig").SetBytes([]byte{0}) // XXX: hack

	// Marshal ...
	mb, err := network.Marshal(m) // TODO: change m to interface with hash to make it compatible to other languages (network.Marshal() adds struct-identifiers)
	if err != nil {
		return err
	}

	// ... and hash message
	hash2, err := hash.Bytes(suite.Hash(), mb)
	if err != nil {
		return err
	}

	// Copy back original signature
	reflect.ValueOf(m).Elem().FieldByName("Sig").SetBytes(sig) // XXX: hack

	// Compare hashes
	if !bytes.Equal(hash1, hash2) {
		return errors.New("Message has a different hash than the given one")
	}

	return nil
}

func (rh *RandHound) handleI1(i1 WI1) error {
	msg := &i1.I1

	// Compute hash of the client's message
	msg.Sig = []byte{0} // XXX: hack
	i1b, err := network.Marshal(msg)
	if err != nil {
		return err
	}

	hi1, err := hash.Bytes(rh.Suite().Hash(), i1b)
	if err != nil {
		return err
	}

	// Gather public keys of the group members
	keys := make([]abstract.Point, len(msg.Group))
	for i, g := range msg.Group {
		keys[i] = rh.TreeNodeInstance.Roster().Get(int(g)).Public // TODO: verify that we are not accessing the wrong keys here
	}

	// Init PVSS and create shares
	H, _ := rh.Suite().Point().Pick(nil, rh.Suite().Cipher(msg.SID))
	encShares, pubPoly, err := pvss.EncShares(rh.Suite(), H, keys, rh.Suite().Scalar().Pick(random.Stream), msg.Threshold)
	if err != nil {
		return err
	}

	// Wrap encrypted shares to keep track of source and target servers
	shares := make([]*Share, len(encShares))
	for i, share := range encShares {
		shares[i] = &Share{
			Source:      rh.TreeNodeInstance.TreeNode().RosterIndex,
			Target:      int(msg.Group[i]),
			PubVerShare: share,
		}
	}

	_, commits := pubPoly.Info()
	r1 := &R1{
		HI1:      hi1,
		EncShare: shares,
		Commit:   commits,
	}

	// Sign R1 and store signature in R1.Sig
	if err := signSchnorr(rh.Suite(), rh.Private(), r1); err != nil {
		return err
	}

	return rh.SendTo(rh.Root(), r1)
}

func (rh *RandHound) handleR1(r1 WR1) error {
	msg := &r1.R1
	idx := r1.RosterIndex
	grp := rh.serverIdxToGroupNum[idx]
	pos := rh.serverIdxToGroupIdx[idx]
	rh.mutex.Lock()
	defer rh.mutex.Unlock()

	// Verify R1 message signature
	if err := verifySchnorr(rh.Suite(), rh.groups[grp].key[pos], msg); err != nil {
		return err
	}

	// Verify that server replied to the correct I1 message
	if err := verifyMessage(rh.Suite(), rh.i1s[grp], msg.HI1); err != nil {
		return err
	}

	// Record R1 message
	rh.r1s[idx] = msg

	// Return, if we already committed to secrets before
	if len(rh.chosenSecret) > 0 {
		return nil
	}

	// Recover commitment polynomials
	H, _ := rh.Suite().Point().Pick(nil, rh.Suite().Cipher(rh.sid))
	pubPoly := share.NewPubPoly(rh.Suite(), H, msg.Commit)
	for _, encShare := range msg.EncShare {
		sH := pubPoly.Eval(encShare.PubVerShare.S.I)
		key := rh.TreeNodeInstance.Roster().Get(encShare.Target).Public
		if pvss.VerifyEncShare(rh.Suite(), H, key, sH, encShare.PubVerShare) == nil {
			if _, ok := rh.evalCommit[idx]; !ok {
				rh.evalCommit[idx] = make([]*share.PubShare, 0)
			}
			if _, ok := rh.secret[idx]; !ok {
				rh.secret[idx] = make([]int, 0)
			}
			rh.evalCommit[idx] = append(rh.evalCommit[idx], sH)
			rh.secret[idx] = append(rh.secret[idx], encShare.Target)
		}
	}

	// Check if there is at least a threshold number of reconstructable secrets
	// in each group. If yes proceed to the next phase. Note the double-usage
	// of the threshold which is used to determine if enough valid shares for a
	// single secret are available and if enough secrets for a given group are
	// available
	goodSecret := make(map[int][]int)
	for i, group := range rh.groups {
		var secret []int
		for _, server := range group.server {
			j := server.RosterIndex
			if share, ok := rh.secret[j]; ok && group.threshold <= len(share) {
				secret = append(secret, j)
			}
		}
		if group.threshold <= len(secret) {
			goodSecret[i] = secret
		}
	}

	// Proceed, if there are enough good secrets
	if len(goodSecret) == len(rh.groups) {

		// Reset secret for the next phase (see handleR2)
		rh.secret = make(map[int][]int)

		for i, group := range rh.groups {
			// Randomly remove some secrets so that a threshold of secrets remain
			rand := random.Bytes(rh.Suite().Hash().Size(), random.Stream)
			prng := rh.Suite().Cipher(rand)
			secret := goodSecret[i]
			for j := 0; j < len(secret)-group.threshold; j++ {
				k := int(random.Uint32(prng) % uint32(len(secret)))
				secret = append(secret[:k], secret[k+1:]...)
			}
			rh.chosenSecret[i] = secret

			log.Lvlf3("Group: %v %v", i, group.index)
		}

		log.Lvlf1("ChosenSecret: %v", rh.chosenSecret)

		// Transformation of commitments from map[int][]int to []uint32 to avoid protobuf errors
		var chosenSecret = make([]uint32, 0)
		for i := 0; i < len(rh.chosenSecret); i++ {
			for _, cs := range rh.chosenSecret[i] {
				chosenSecret = append(chosenSecret, uint32(cs))
			}
		}

		// Prepare a message for each server of a group and send it
		for i, group := range rh.groups {
			for j, server := range group.server {

				// Among the good secrets chosen previously collect all valid
				// shares, proofs, and polynomial commits intended for the
				// target server
				var encShare []*Share
				var commit []*share.PubShare
				for _, k := range rh.chosenSecret[i] {
					r1 := rh.r1s[k]
					ec := rh.evalCommit[k]
					encShare = append(encShare, r1.EncShare[j])
					commit = append(commit, ec[j])
				}

				i2 := &I2{
					Sig:          []byte{0},
					SID:          rh.sid,
					ChosenSecret: chosenSecret,
					EncShare:     encShare,
					EvalCommit:   commit,
				}

				if err := signSchnorr(rh.Suite(), rh.Private(), i2); err != nil {
					return err
				}

				rh.i2s[server.RosterIndex] = i2

				if err := rh.SendTo(server, i2); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (rh *RandHound) handleI2(i2 WI2) error {
	msg := &i2.I2

	// Compute hash of the client's message
	msg.Sig = []byte{0} // XXX: hack
	i2b, err := network.Marshal(msg)
	if err != nil {
		return err
	}

	hi2, err := crypto.HashBytes(rh.Suite().Hash(), i2b)
	if err != nil {
		return err
	}

	H, _ := rh.Suite().Point().Pick(nil, rh.Suite().Cipher(msg.SID))
	decShares := make([]*Share, 0)
	for i, share := range msg.EncShare {
		decShare, err := pvss.DecShare(rh.Suite(), H, rh.Public(), msg.EvalCommit[i], rh.Private(), share.PubVerShare)
		if err == nil {
			s := &Share{
				Source:      share.Source,
				Target:      share.Target,
				PubVerShare: decShare,
			}
			decShares = append(decShares, s)
		}
	}

	r2 := &R2{
		HI2:      hi2,
		DecShare: decShares,
	}

	if err := signSchnorr(rh.Suite(), rh.Private(), r2); err != nil {
		return err
	}

	return rh.SendTo(rh.Root(), r2)
}

func (rh *RandHound) handleR2(r2 WR2) error {
	msg := &r2.R2
	idx := r2.RosterIndex
	grp := rh.serverIdxToGroupNum[idx]
	pos := rh.serverIdxToGroupIdx[idx]
	rh.mutex.Lock()
	defer rh.mutex.Unlock()

	// If the collective secret is already available, ignore all further incoming messages
	if rh.SecretReady {
		return nil
	}

	// Verify R2 message signature
	if err := verifySchnorr(rh.Suite(), rh.groups[grp].key[pos], msg); err != nil {
		return err
	}

	// Verify that server replied to the correct I2 message
	if err := verifyMessage(rh.Suite(), rh.i2s[idx], msg.HI2); err != nil {
		return err
	}

	// Record R2 message
	rh.r2s[idx] = msg

	// Verify decrypted shares and record valid ones
	G := rh.Suite().Point().Base()
	for _, share := range msg.DecShare {
		src := share.Source
		X := rh.groups[grp].key[pos]
		encShare := rh.r1s[src].EncShare[pos].PubVerShare
		decShare := share.PubVerShare
		if pvss.VerifyDecShare(rh.Suite(), G, X, encShare, decShare) == nil {
			if _, ok := rh.records[src]; !ok {
				rh.records[src] = make([]*Record, 0)
			}
			r := &Record{
				Key:      X,
				EncShare: encShare,
				DecShare: decShare,
			}
			rh.records[src] = append(rh.records[src], r)
		}
	}

	proceed := true
	for i, group := range rh.chosenSecret {
		for _, server := range group {
			if len(rh.records[server]) < rh.groups[i].threshold {
				proceed = false
			}
		}
	}

	if len(rh.r2s) == rh.nodes-1 && !proceed {
		rh.Done <- true
		return errors.New("some chosen secrets are not reconstructable")
	}

	if proceed && !rh.SecretReady {
		rh.SecretReady = true
		rh.Done <- true
	}
	return nil
}

func (rh *RandHound) handleI3(i3 WI3) error {

	return nil
}

func (rh *RandHound) handleR3(r3 WR3) error {
	return nil
}
