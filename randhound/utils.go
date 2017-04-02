package randhound

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/hash"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/share/pvss"
	"github.com/dedis/crypto/sign"
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
)

func (rh *RandHound) newSession(nodes int, groups int, purpose string, timestamp time.Time, seed []byte, clientKey abstract.Point) (*Session, error) {

	var err error

	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	if seed == nil {
		seed = random.Bytes(rh.Suite().Hash().Size(), random.Stream)
	}

	// Shard servers
	indices, err := rh.Shard(seed, nodes, groups)
	if err != nil {
		return nil, err
	}

	// Setup group information
	treeNodes := rh.List()
	servers := make([][]*onet.TreeNode, groups)
	serverKeys := make([][]abstract.Point, groups)
	thresholds := make([]int, groups)
	groupNum := make(map[int]int)
	groupPos := make(map[int]int)
	for i, group := range indices {
		s := make([]*onet.TreeNode, len(group))
		k := make([]abstract.Point, len(group))
		for j, g := range group {
			s[j] = treeNodes[g]
			k[j] = treeNodes[g].ServerIdentity.Public
			groupNum[g] = i
			groupPos[g] = j
		}
		servers[i] = s
		serverKeys[i] = k
		thresholds[i] = len(s)/3 + 1
	}

	// Compute session identifier
	sid, err := rh.sessionID(clientKey, serverKeys, indices, purpose, timestamp)
	if err != nil {
		return nil, err
	}

	// Setup session
	session := &Session{
		nodes:      nodes,
		groups:     groups,
		purpose:    purpose,
		time:       timestamp,
		seed:       seed,
		clientKey:  clientKey,
		sid:        sid,
		servers:    servers,
		serverKeys: serverKeys,
		indices:    indices,
		thresholds: thresholds,
		groupNum:   groupNum,
		groupPos:   groupPos,
	}

	return session, nil
}

func (rh *RandHound) sessionID(clientKey abstract.Point, serverKeys [][]abstract.Point, indices [][]int, purpose string, timestamp time.Time) ([]byte, error) {
	// Setup some buffers
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

	// Process server keys and group indices
	for i, _ := range serverKeys {
		for j, _ := range serverKeys[i] {
			kb, err := serverKeys[i][j].MarshalBinary()
			if err != nil {
				return nil, err
			}
			if _, err := keyBuf.Write(kb); err != nil {
				return nil, err
			}
			if err := binary.Write(idxBuf, binary.LittleEndian, uint32(indices[i][j])); err != nil {
				return nil, err
			}
		}
	}

	// Process purpose string
	if _, err := miscBuf.WriteString(purpose); err != nil {
		return nil, err
	}

	// Process time stamp
	t, err := timestamp.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if _, err := miscBuf.Write(t); err != nil {
		return nil, err
	}

	return hash.Bytes(rh.Suite().Hash(), keyBuf.Bytes(), idxBuf.Bytes(), miscBuf.Bytes())
}

func recoverRandomness(suite abstract.Suite, sid []byte, keys []abstract.Point, thresholds []int, groupNum map[int]int, indices [][]int, records map[int]map[int]*Record) ([]byte, error) {
	rnd := suite.Point().Null()
	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher(sid))
	for src, _ := range records {
		var groupKeys []abstract.Point
		var encShares []*pvss.PubVerShare
		var decShares []*pvss.PubVerShare
		for tgt, record := range records[src] {
			if record.Eval != nil && record.EncShare != nil && record.DecShare != nil {
				if pvss.VerifyEncShare(suite, H, keys[tgt], record.Eval, record.EncShare) == nil {
					groupKeys = append(groupKeys, keys[tgt])
					encShares = append(encShares, record.EncShare)
					decShares = append(decShares, record.DecShare) // NOTE: decrypted shares will be verified during recovery
				}
			}
		}
		grp := groupNum[src]
		ps, err := pvss.RecoverSecret(suite, G, groupKeys, encShares, decShares, thresholds[grp], len(indices[grp]))
		if err != nil {
			return nil, err
		}
		rnd = suite.Point().Add(rnd, ps)
	}
	rb, err := rnd.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return rb, nil
}

func chosenSecrets(records map[int]map[int]*Record) []uint32 {
	var chosenSecrets []uint32
	for src, _ := range records {
		chosenSecrets = append(chosenSecrets, uint32(src))
	}
	sort.Slice(chosenSecrets, func(i, j int) bool {
		return chosenSecrets[i] < chosenSecrets[j]
	})
	return chosenSecrets
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
		return errors.New("wrong message content")
	}

	return nil
}
