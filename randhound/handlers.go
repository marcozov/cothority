package randhound

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cosi"
	"github.com/dedis/crypto/hash"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/share"
	"github.com/dedis/crypto/share/pvss"
	"github.com/dedis/onet/network"
)

// Some error definitions.
var errorWrongSession = errors.New("wrong session identifier")

func (rh *RandHound) handleI1(i1 WI1) error {
	msg := &i1.I1
	var err error
	src := i1.RosterIndex
	idx := rh.TreeNode().RosterIndex
	keys := rh.Roster().Publics()
	nodes := len(keys)
	clientKey := keys[src]

	// Verify I1 message signature
	if err := verifySchnorr(rh.Suite(), clientKey, msg); err != nil {
		return err
	}

	// Setup session
	if rh.Session, err = rh.newSession(nodes, msg.Groups, msg.Purpose, msg.Time, msg.Seed, clientKey); err != nil {
		return err
	}

	// Verify session identifier
	if !bytes.Equal(rh.sid, msg.SID) {
		return errorWrongSession
	}

	// Setup CoSi instance
	rh.CoSi = cosi.NewCosi(rh.Suite(), rh.Private(), rh.Roster().Publics())

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
	grp := rh.groupNum[idx]
	groupKeys := rh.serverKeys[grp]
	t := rh.thresholds[grp]
	secret := rh.Suite().Scalar().Pick(random.Stream)
	H, _ := rh.Suite().Point().Pick(nil, rh.Suite().Cipher(msg.SID))
	encShares, pubPoly, err := pvss.EncShares(rh.Suite(), H, groupKeys, secret, t)
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
	_, coeffs := pubPoly.Info()
	r1 := &R1{
		SID:       rh.sid,
		HI1:       hi1,
		EncShares: shares,
		Coeffs:    coeffs,
		V:         rh.CoSi.CreateCommitment(random.Stream),
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
	grp := rh.groupNum[src]
	pos := rh.groupPos[src]
	rh.mutex.Lock()
	defer rh.mutex.Unlock()

	// Verify R1 message signature
	if err := verifySchnorr(rh.Suite(), rh.serverKeys[grp][pos], msg); err != nil {
		return err
	}

	// Verify session identifier
	if !bytes.Equal(rh.sid, msg.SID) {
		return errorWrongSession
	}

	// Verify that the server replied to the correct I1 message
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
	pubPoly := share.NewPubPoly(rh.Suite(), H, msg.Coeffs)

	// Verify encrypted shares and record valid ones
	for _, encShare := range msg.EncShares {
		pos := encShare.PubVerShare.S.I
		sH := pubPoly.Eval(pos).V
		key := rh.serverKeys[grp][pos]
		if pvss.VerifyEncShare(rh.Suite(), H, key, sH, encShare.PubVerShare) == nil {
			src := encShare.Source
			tgt := encShare.Target
			if _, ok := rh.records[src]; !ok {
				rh.records[src] = make(map[int]*Record)
			}
			rh.records[src][tgt] = &Record{
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

		for i, _ := range rh.servers {
			// Randomly remove some secrets so that a threshold of secrets remain
			rand := random.Bytes(rh.Suite().Hash().Size(), random.Stream)
			prng := rh.Suite().Cipher(rand)
			secrets := goodSecrets[i]
			l := len(secrets) - rh.thresholds[i]
			for j := 0; j < l; j++ {
				k := int(random.Uint32(prng) % uint32(len(secrets)))
				delete(rh.records, secrets[k]) // XXX: check that this works!!!!
			}
		}

		// Recover chosen secrets from records
		rh.chosenSecrets = chosenSecrets(rh.records)

		// Clear CoSi mask
		for i := 0; i < rh.nodes; i++ {
			rh.CoSi.SetMaskBit(i, false)
		}

		// Set our own masking bit
		rh.CoSi.SetMaskBit(rh.TreeNode().RosterIndex, true)

		// Collect commits and mark participating nodes
		rh.e = make([]int, 0)
		subComms := make([]abstract.Point, 0)
		for i, msg := range rh.r1s {
			subComms = append(subComms, msg.V)
			rh.CoSi.SetMaskBit(i, true)
			rh.e = append(rh.e, i)
		}

		// Compute aggregate commit
		rh.CoSi.Commit(random.Stream, subComms)

		// Compute message: statement = SID || chosen secrets
		buf := new(bytes.Buffer)
		if _, err := buf.Write(rh.sid); err != nil {
			return err
		}
		for _, cs := range rh.chosenSecrets {
			binary.Write(buf, binary.LittleEndian, cs)
		}
		rh.statement = buf.Bytes()

		// Compute CoSi challenge
		if _, err := rh.CoSi.CreateChallenge(rh.statement); err != nil {
			return err
		}

		// Prepare a message for each server of a group and send it
		for i, servers := range rh.servers {
			for _, server := range servers {
				// Among the good secrets chosen previously collect all valid
				// shares, proofs, and polynomial commits intended for the
				// target server
				var encShares []*Share
				var evals []abstract.Point
				src := server.RosterIndex
				for _, tgt := range rh.indices[i] {
					if _, ok := rh.records[tgt][src]; ok {
						record := rh.records[tgt][src]
						encShare := &Share{
							Source:      tgt, // NOTE: this swap is correct!
							Target:      src, // NOTE: this swap is correct!
							PubVerShare: record.EncShare,
						}
						encShares = append(encShares, encShare)
						evals = append(evals, record.Eval)
					}
				}
				i2 := &I2{
					Sig:           []byte{0},
					SID:           rh.sid,
					ChosenSecrets: rh.chosenSecrets,
					EncShares:     encShares,
					Evals:         evals,
					C:             rh.CoSi.GetChallenge(),
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
	if err := verifySchnorr(rh.Suite(), rh.clientKey, msg); err != nil {
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

	// Record chosen secrets
	rh.chosenSecrets = msg.ChosenSecrets

	// TODO: Check that the chosen secrets satisfy the thresholds
	//for i, secrets := range rh.chosenSecrets {
	//	if len(secrets) != len(rh.servers[i])/3+1 {
	//		return fmt.Errorf("wrong threshold")
	//	}
	//}

	if !(rh.nodes/3 < len(msg.ChosenSecrets)) {
		return fmt.Errorf("not enough chosen secrets")
	}

	rh.CoSi.Challenge(msg.C)
	r, err := rh.CoSi.CreateResponse()
	if err != nil {
		return err
	}

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

	return rh.SendTo(rh.Root(), r2)
}

func (rh *RandHound) handleR2(r2 WR2) error {
	msg := &r2.R2
	src := r2.RosterIndex
	grp := rh.groupNum[src]
	pos := rh.groupPos[src]
	rh.mutex.Lock()
	defer rh.mutex.Unlock()

	// Verify R2 message signature
	if err := verifySchnorr(rh.Suite(), rh.serverKeys[grp][pos], msg); err != nil {
		return err
	}

	// Verify session identifier
	if !bytes.Equal(rh.sid, msg.SID) {
		return errorWrongSession
	}

	// Verify that server replied to the correct I2 message
	if err := verifyMessage(rh.Suite(), rh.i2s[src], msg.HI2); err != nil {
		return err
	}

	// Record R2 message
	rh.r2s[src] = msg

	// TODO: What condition to proceed?
	if len(rh.r2s) == rh.nodes-1 {
		responses := make([]abstract.Scalar, 0)
		for _, src := range rh.e {
			responses = append(responses, rh.r2s[src].R)
		}
		if _, err := rh.CoSi.Response(responses); err != nil {
			return err
		}
		rh.CoSig = rh.CoSi.Signature()
		if err := cosi.VerifySignature(rh.Suite(), rh.Roster().Publics(), rh.statement, rh.CoSig); err != nil {
			return err
		}
		rh.i3 = &I3{
			SID:   rh.sid,
			CoSig: rh.CoSig,
		}
		if err := signSchnorr(rh.Suite(), rh.Private(), rh.i3); err != nil {
			return err
		}
		if err := rh.Broadcast(rh.i3); err != nil {
			return err
		}
	}
	return nil
}

func (rh *RandHound) handleI3(i3 WI3) error {
	msg := &i3.I3
	src := i3.RosterIndex

	// Verify I3 message signature
	if err := verifySchnorr(rh.Suite(), rh.clientKey, msg); err != nil {
		return err
	}

	// Verify session identifier
	if !bytes.Equal(rh.sid, msg.SID) {
		return errorWrongSession
	}

	// Compute message: statement = SID || chosen secrets
	buf := new(bytes.Buffer)
	if _, err := buf.Write(rh.sid); err != nil {
		return err
	}
	for _, cs := range rh.i2s[src].ChosenSecrets {
		binary.Write(buf, binary.LittleEndian, cs)
	}
	rh.statement = buf.Bytes()

	// Verify collective signature (TODO: check that more than 2/3 of participants have signed)
	if err := cosi.VerifySignature(rh.Suite(), rh.Roster().Publics(), rh.statement, msg.CoSig); err != nil {
		return err
	}

	// Compute hash of the client's message
	msg.Sig = []byte{0} // XXX: hack
	i3b, err := network.Marshal(msg)
	if err != nil {
		return err
	}

	hi3, err := hash.Bytes(rh.Suite().Hash(), i3b)
	if err != nil {
		return err
	}

	H, _ := rh.Suite().Point().Pick(nil, rh.Suite().Cipher(msg.SID))
	decShares := make([]*Share, 0)
	for i, share := range rh.i2s[src].EncShares {
		decShare, err := pvss.DecShare(rh.Suite(), H, rh.Public(), rh.i2s[src].Evals[i], rh.Private(), share.PubVerShare)
		if err == nil {
			s := &Share{
				Source:      share.Source,
				Target:      share.Target,
				PubVerShare: decShare,
			}
			decShares = append(decShares, s)
		}
	}

	r3 := &R3{
		SID:       rh.sid,
		HI3:       hi3,
		DecShares: decShares,
	}

	if err := signSchnorr(rh.Suite(), rh.Private(), r3); err != nil {
		return err
	}

	return rh.SendTo(rh.Root(), r3)
}

func (rh *RandHound) handleR3(r3 WR3) error {
	msg := &r3.R3
	idx := r3.RosterIndex
	grp := rh.groupNum[idx]
	pos := rh.groupPos[idx]
	rh.mutex.Lock()
	defer rh.mutex.Unlock()

	// If the collective secret is already available, ignore all further incoming messages
	if rh.SecretReady {
		return nil
	}

	// Verify R3 message signature
	if err := verifySchnorr(rh.Suite(), rh.serverKeys[grp][pos], msg); err != nil {
		return err
	}

	// Verify that server replied to the correct I3 message
	if err := verifyMessage(rh.Suite(), rh.i3, msg.HI3); err != nil {
		return err
	}

	// Record R3 message
	rh.r3s[idx] = msg

	// Verify decrypted shares and record valid ones
	G := rh.Suite().Point().Base()
	K := rh.Roster().Publics()
	for _, share := range msg.DecShares {
		src := share.Source
		tgt := share.Target
		if _, ok := rh.records[src][tgt]; !ok {
			continue
		}
		r := rh.records[src][tgt]
		X := K[tgt]
		encShare := r.EncShare
		decShare := share.PubVerShare
		if pvss.VerifyDecShare(rh.Suite(), G, X, encShare, decShare) == nil {
			r.DecShare = decShare
			rh.records[src][tgt] = r
		}
	}

	proceed := true
	for src, records := range rh.records {
		c := 0
		for _, record := range records {
			if record.EncShare != nil && record.DecShare != nil {
				c += 1
			}
		}
		grp := rh.groupNum[src]
		if c < rh.thresholds[grp] {
			proceed = false
		}
	}

	//for i, group := range rh.chosenSecrets {
	//	for _, src := range group {
	//		c := 0 // enough shares?
	//		for _, record := range rh.records[src] {
	//			if record.EncShare != nil && record.DecShare != nil {
	//				c += 1
	//			}
	//		}
	//		if c < rh.thresholds[i] {
	//			proceed = false
	//		}
	//	}
	//}

	if len(rh.r3s) == rh.nodes-1 && !proceed {
		rh.Done <- true
		return errors.New("some chosen secrets are not reconstructable")
	}

	if proceed && !rh.SecretReady {
		rh.SecretReady = true
		rh.Done <- true
	}
	return nil
}
