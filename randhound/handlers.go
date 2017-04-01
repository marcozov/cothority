package randhound

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/hash"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/share"
	"github.com/dedis/crypto/share/pvss"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

// Some error definitions.
var errorWrongSession = errors.New("wrong session identifier")

func (rh *RandHound) handleI1(i1 WI1) error {
	msg := &i1.I1
	src := i1.RosterIndex
	idx := rh.TreeNode().RosterIndex

	rh.nodes = len(rh.Roster().List)
	rh.client = rh.Roster().List[src].Public

	// Verify I1 message signature
	if err := verifySchnorr(rh.Suite(), rh.client, msg); err != nil {
		return err
	}

	// Store received session parameters
	rh.groups = msg.Groups
	rh.purpose = msg.Purpose
	rh.time = msg.Time
	rh.seed = msg.Seed

	// Setup remaining session information
	if err := rh.setupSession(); err != nil {
		return err
	}

	// Verify session identifier
	if !bytes.Equal(rh.sid, msg.SID) {
		return errorWrongSession
	}

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

	// Compute encrypted PVSS shares for group members
	grp := rh.rosterIdxToGroupNum[idx]
	keys := rh.keys[grp]
	t := rh.thresholds[grp]
	secret := rh.Suite().Scalar().Pick(random.Stream)
	H, _ := rh.Suite().Point().Pick(nil, rh.Suite().Cipher(msg.SID))
	encShares, pubPoly, err := pvss.EncShares(rh.Suite(), H, keys, secret, t)
	if err != nil {
		return err
	}

	// Wrap encrypted shares to keep track of source and target servers
	shares := make([]*Share, len(encShares))
	for i, share := range encShares {
		shares[i] = &Share{
			Source:      rh.TreeNode().RosterIndex,
			Target:      rh.servers[grp][i].RosterIndex,
			PubVerShare: share,
		}
	}

	// Setup R1 message
	_, commits := pubPoly.Info()
	rh.v = rh.Suite().Scalar().Pick(random.Stream)
	r1 := &R1{
		SID:       rh.sid,
		HI1:       hi1,
		EncShares: shares,
		Commit:    commits,
		V:         rh.Suite().Point().Mul(nil, rh.v),
	}

	// Sign R1 message
	if err := signSchnorr(rh.Suite(), rh.Private(), r1); err != nil {
		return err
	}

	// Send R1 message
	return rh.SendTo(rh.Root(), r1)
}

func (rh *RandHound) handleR1(r1 WR1) error {
	msg := &r1.R1
	src := r1.RosterIndex
	grp := rh.rosterIdxToGroupNum[src]
	pos := rh.rosterIdxToGroupPos[src]
	rh.mutex.Lock()
	defer rh.mutex.Unlock()

	// Verify R1 message signature
	if err := verifySchnorr(rh.Suite(), rh.keys[grp][pos], msg); err != nil {
		return err
	}

	// Verify session identifier
	if !bytes.Equal(rh.sid, msg.SID) {
		return errorWrongSession
	}

	// Verify that server replied to the correct I1 message
	if err := verifyMessage(rh.Suite(), rh.i1, msg.HI1); err != nil {
		return err
	}

	// Record R1 message
	rh.r1s[src] = msg

	// Return, if we already committed to secrets before
	if len(rh.chosenSecrets) > 0 {
		return nil
	}

	// Recover commitment polynomial
	H, _ := rh.Suite().Point().Pick(nil, rh.Suite().Cipher(rh.sid))
	pubPoly := share.NewPubPoly(rh.Suite(), H, msg.Commit)

	// Verify encrypted shares and record valid ones
	for _, encShare := range msg.EncShares {
		pos := encShare.PubVerShare.S.I
		sH := pubPoly.Eval(pos).V
		key := rh.keys[grp][pos]
		if pvss.VerifyEncShare(rh.Suite(), H, key, sH, encShare.PubVerShare) == nil {
			src := encShare.Source
			tgt := encShare.Target
			if _, ok := rh.records[src]; !ok {
				rh.records[src] = make(map[int]*Record)
			}
			rh.records[src][tgt] = &Record{
				Key:      key,
				Eval:     sH,
				EncShare: encShare.PubVerShare,
				DecShare: nil,
			}
		}
	}

	// Check if there is at least a threshold number of reconstructable secrets
	// in each group. If yes proceed to the next phase. Note the double-usage
	// of the threshold which is used to determine if enough valid shares for a
	// single secret are available and if enough secrets for a given group are
	// available
	goodSecrets := make(map[int][]int)
	for i, servers := range rh.servers {
		var secret []int
		for _, server := range servers {
			src := server.RosterIndex
			if shares, ok := rh.records[src]; ok && rh.thresholds[i] <= len(shares) {
				secret = append(secret, src)
			}
		}
		if rh.thresholds[i] <= len(secret) {
			goodSecrets[i] = secret
		}
	}

	// Proceed, if there are enough good secrets and more than 2/3 of servers replied
	if len(goodSecrets) == rh.groups && 2*rh.nodes/3 < len(rh.r1s) {

		buf := new(bytes.Buffer)
		chosenSecrets := make([]uint32, 0)
		for i, _ := range rh.servers {
			// Randomly remove some secrets so that a threshold of secrets remain
			rand := random.Bytes(rh.Suite().Hash().Size(), random.Stream)
			prng := rh.Suite().Cipher(rand)
			secrets := goodSecrets[i]
			l := len(secrets) - rh.thresholds[i]
			for j := 0; j < l; j++ {
				k := int(random.Uint32(prng) % uint32(len(secrets)))
				secrets = append(secrets[:k], secrets[k+1:]...)
			}
			// TODO: take care of the mess between chosenSecrets and rh.chosenSecrets!
			for j := 0; j < len(secrets); j++ {
				chosenSecrets = append(chosenSecrets, uint32(secrets[j]))
				binary.Write(buf, binary.LittleEndian, secrets[j])
			}
			rh.chosenSecrets[i] = secrets
			//log.Lvlf1("Group: %v %v %v", i, rh.thresholds[i], rh.indices[i])
		}

		log.Lvlf1("ChosenSecrets: %v", rh.chosenSecrets)

		rh.V = rh.Suite().Point().Null()
		rh.e = make([]int, 0)

		// Compute aggregate commit and mark nodes that participated
		for i, msg := range rh.r1s {
			rh.V.Add(rh.V, msg.V)
			rh.e = append(rh.e, i)
		}
		vb, err := rh.V.MarshalBinary()
		if err != nil {
			return err
		}

		// Compute challenge
		c, err := hash.Bytes(rh.Suite().Hash(), vb, rh.sid, buf.Bytes())
		if err != nil {
			return err
		}
		rh.c = c

		// Prepare a message for each server of a group and send it
		for i, servers := range rh.servers {
			for _, server := range servers {
				// Among the good secrets chosen previously collect all valid
				// shares, proofs, and polynomial commits intended for the
				// target server
				var encShares []*Share
				var evals []abstract.Point
				src := server.RosterIndex
				for _, tgt := range rh.chosenSecrets[i] {
					r := rh.records[tgt][src]
					encShare := &Share{
						Source:      tgt, // NOTE: this swap is correct!
						Target:      src, // NOTE: this swap is correct!
						PubVerShare: r.EncShare,
					}
					encShares = append(encShares, encShare)
					evals = append(evals, r.Eval)
				}
				i2 := &I2{
					Sig:           []byte{0},
					SID:           rh.sid,
					ChosenSecrets: chosenSecrets,
					EncShares:     encShares,
					Evals:         evals,
					C:             rh.c,
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
	src := i2.RosterIndex

	// Verify I2 message signature
	if err := verifySchnorr(rh.Suite(), rh.client, msg); err != nil {
		return err
	}

	// Verify session identifier
	if !bytes.Equal(rh.sid, msg.SID) {
		return errorWrongSession
	}

	// Store the client's message
	rh.i2s = make(map[int]*I2)
	rh.i2s[src] = msg

	// Compute hash of the client's message
	msg.Sig = []byte{0} // XXX: hack
	i2b, err := network.Marshal(msg)
	if err != nil {
		return err
	}

	hi2, err := hash.Bytes(rh.Suite().Hash(), i2b)
	if err != nil {
		return err
	}
	_ = hi2

	// Record chosen secrets
	rh.chosenSecrets = make(map[int][]int)
	for _, cs := range msg.ChosenSecrets {
		grp := rh.rosterIdxToGroupNum[int(cs)]
		if _, ok := rh.chosenSecrets[grp]; !ok {
			rh.chosenSecrets[grp] = make([]int, 0)
		}
		rh.chosenSecrets[grp] = append(rh.chosenSecrets[grp], int(cs))
	}

	// Check that the chosen secrets satisfy the thresholds
	for i, secrets := range rh.chosenSecrets {
		if len(secrets) != len(rh.servers[i])/3+1 {
			return fmt.Errorf("wrong threshold")
		}
	}

	if !(rh.nodes/3 < len(msg.ChosenSecrets)) {
		return fmt.Errorf("not enough chosen secrets")
	}

	// Compute the response r = v - cx
	c := rh.Suite().Scalar().SetBytes(msg.C)
	cx := rh.Suite().Scalar().Mul(c, rh.Private())
	r := rh.Suite().Scalar().Sub(rh.v, cx)

	// Setup R2 message
	r2 := &R2{
		SID: rh.sid,
		HI2: hi2,
		R:   r,
	}

	// Sign R2 message
	if err := signSchnorr(rh.Suite(), rh.Private(), r2); err != nil {
		return err
	}

	// Send R2 message back to the client
	return nil
	//return rh.SendTo(rh.Root(), r2)
}

func (rh *RandHound) handleR2(r2 WR2) error {
	msg := &r2.R2

	// Verify session identifier
	if !bytes.Equal(rh.sid, msg.SID) {
		return errorWrongSession
	}

	return nil
}

func (rh *RandHound) handleI3(i3 WI3) error {
	return nil
}

func (rh *RandHound) handleR3(r3 WR3) error {
	return nil
}

//func (rh *RandHound) handleI3(i3 WI3) error {
//	msg := &i3.I3
//
//	// Verify signature
//
//	// Verify session identifier
//	if !bytes.Equal(rh.sid, msg.SID) {
//		return errorWrongSession
//	}
//
//	// Compute hash of the client's message
//	msg.Sig = []byte{0} // XXX: hack
//	i2b, err := network.Marshal(msg)
//	if err != nil {
//		return err
//	}
//
//	hi2, err := hash.Bytes(rh.Suite().Hash(), i2b)
//	if err != nil {
//		return err
//	}
//
//	H, _ := rh.Suite().Point().Pick(nil, rh.Suite().Cipher(msg.SID))
//	decShares := make([]*Share, 0)
//	for i, share := range msg.EncShares {
//		decShare, err := pvss.DecShare(rh.Suite(), H, rh.Public(), msg.Evals[i], rh.Private(), share.PubVerShare)
//		if err == nil {
//			s := &Share{
//				Source:      share.Source,
//				Target:      share.Target,
//				PubVerShare: decShare,
//			}
//			decShares = append(decShares, s)
//		}
//	}
//
//	r2 := &R2{
//		HI2:       hi2,
//		DecShares: decShares,
//	}
//
//	if err := signSchnorr(rh.Suite(), rh.Private(), r2); err != nil {
//		return err
//	}
//
//	return rh.SendTo(rh.Root(), r2)
//}

//func (rh *RandHound) handleR3(r2 WR3) error {
//	msg := &r3.R3
//	idx := r2.RosterIndex
//	grp := rh.rosterIdxToGroupNum[idx]
//	pos := rh.rosterIdxToGroupPos[idx]
//	rh.mutex.Lock()
//	defer rh.mutex.Unlock()
//
//	// If the collective secret is already available, ignore all further incoming messages
//	if rh.SecretReady {
//		return nil
//	}
//
//	// Verify R2 message signature
//	if err := verifySchnorr(rh.Suite(), rh.keys[grp][pos], msg); err != nil {
//		return err
//	}
//
//	// Verify that server replied to the correct I2 message
//	if err := verifyMessage(rh.Suite(), rh.i2s[idx], msg.HI2); err != nil {
//		return err
//	}
//
//	// Record R2 message
//	rh.r2s[idx] = msg
//
//	// Verify decrypted shares and record valid ones
//	G := rh.Suite().Point().Base()
//	for _, share := range msg.DecShares {
//		src := share.Source
//		tgt := share.Target
//		if _, ok := rh.records[src][tgt]; !ok {
//			continue
//		}
//		r := rh.records[src][tgt]
//		X := r.Key
//		encShare := r.EncShare
//		decShare := share.PubVerShare
//		if pvss.VerifyDecShare(rh.Suite(), G, X, encShare, decShare) == nil {
//			r.DecShare = decShare
//			rh.records[src][tgt] = r
//		}
//	}
//
//	proceed := true
//	for i, group := range rh.chosenSecrets {
//		for _, src := range group {
//			c := 0 // enough shares?
//			for _, r := range rh.records[src] {
//				if r.Key != nil && r.EncShare != nil && r.DecShare != nil {
//					c += 1
//				}
//			}
//			if c < rh.thresholds[i] {
//				proceed = false
//			}
//		}
//	}
//
//	if len(rh.r2s) == rh.nodes-1 && !proceed {
//		rh.Done <- true
//		return errors.New("some chosen secrets are not reconstructable")
//	}
//
//	if proceed && !rh.SecretReady {
//		rh.SecretReady = true
//		rh.Done <- true
//	}
//	return nil
//}
