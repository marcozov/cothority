package randhound

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/hash"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/sign"
	"github.com/dedis/onet/network"
)

func (rh *RandHound) newSession(nodes int, groups int, purpose string, t time.Time, seed []byte, client abstract.Point) (*Session, error) {

	var err error

	indices := make([][]int, groups)
	thresholds := make([]int, groups)
	groupNum := make(map[int]int)
	groupPos := make(map[int]int)

	if t.IsZero() {
		t = time.Now()
	}

	if seed == nil {
		seed = random.Bytes(rh.Suite().Hash().Size(), random.Stream)
	}

	// Shard servers
	servers, err := rh.Shard(rh.List(), seed, groups)
	if err != nil {
		return nil, err
	}

	// Setup group information
	keys := make([][]abstract.Point, groups)
	for i, servers := range servers {
		idx := make([]int, len(servers))
		key := make([]abstract.Point, len(servers))
		for j, server := range servers {
			k := server.RosterIndex
			groupNum[k] = i
			groupPos[k] = j
			idx[j] = k
			key[j] = server.ServerIdentity.Public
		}
		indices[i] = idx
		thresholds[i] = len(servers)/3 + 1
		keys[i] = key
	}

	// Compute session identifier
	sid, err := rh.sessionID(client, keys, indices, purpose, t)
	if err != nil {
		return nil, err
	}

	// Setup session
	session := &Session{
		nodes:      nodes,
		groups:     groups,
		purpose:    purpose,
		time:       t,
		seed:       seed,
		client:     client,
		sid:        sid,
		servers:    servers,
		keys:       keys,
		indices:    indices,
		thresholds: thresholds,
		groupNum:   groupNum,
		groupPos:   groupPos,
	}

	return session, nil
}

func (rh *RandHound) sessionID(client abstract.Point, keys [][]abstract.Point, groups [][]int, purpose string, time time.Time) ([]byte, error) {
	// Setup some buffers
	keyBuf := new(bytes.Buffer)
	idxBuf := new(bytes.Buffer)
	miscBuf := new(bytes.Buffer)

	// Process client key
	cb, err := client.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err := keyBuf.Write(cb); err != nil {
		return nil, err
	}

	// Process server keys and group indices
	for i, _ := range keys {
		for j, _ := range keys[i] {
			kb, err := keys[i][j].MarshalBinary()
			if err != nil {
				return nil, err
			}
			if _, err := keyBuf.Write(kb); err != nil {
				return nil, err
			}
			if err := binary.Write(idxBuf, binary.LittleEndian, uint32(groups[i][j])); err != nil {
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

	return hash.Bytes(rh.Suite().Hash(), keyBuf.Bytes(), idxBuf.Bytes(), miscBuf.Bytes())
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
