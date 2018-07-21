package cttestsrv

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/util"
	"github.com/google/trillian"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/log"
	"github.com/google/trillian/merkle/hashers"
	"github.com/google/trillian/quota"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/storage/memory"
	"github.com/google/trillian/trees"
	"github.com/google/trillian/types"

	_ "github.com/google/trillian/crypto/keys/der/proto" // PrivateKey proto handler
	_ "github.com/google/trillian/crypto/keys/pem/proto" // PEMKeyFile proto handler
	_ "github.com/google/trillian/merkle/rfc6962"        // Make hashers available
)

var (
	timeSource = util.SystemTimeSource{}
)

type testLog struct {
	tree *trillian.Tree
	root *trillian.SignedLogRoot

	key    *ecdsa.PrivateKey
	hasher hashers.LogHasher
	signer *tcrypto.Signer

	logStorage   storage.LogStorage
	adminStorage storage.AdminStorage

	sequencer *log.Sequencer
}

func newLog(key *ecdsa.PrivateKey, pubKeyBytes []byte) (*testLog, error) {
	keyBytes, err := der.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}

	pk, err := ptypes.MarshalAny(&keyspb.PrivateKey{
		Der: keyBytes,
	})
	if err != nil {
		return nil, err
	}

	// See https://github.com/google/trillian/blob/master/storage/testonly/admin_storage_tester.go
	tree := &trillian.Tree{
		TreeId:             0,
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_LOG,
		HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        "Test Log",
		Description:        "ct-test-server test log",
		PrivateKey:         pk,
		PublicKey: &keyspb.PublicKey{
			Der: pubKeyBytes,
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}

	logStorage := memory.NewLogStorage(nil)
	adminStorage := memory.NewAdminStorage(logStorage)

	// overwrite the tree with the one returned from CreateTree since it will populate a TreeId
	tree, err = storage.CreateTree(context.Background(), adminStorage, tree)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Created in-memory tree with ID: %#v\n", tree.TreeId)

	hasher, err := hashers.NewLogHasher(tree.HashStrategy)
	if err != nil {
		return nil, err
	}

	signer, err := trees.Signer(context.Background(), tree)
	if err != nil {
		return nil, err
	}

	// init the new tree by signing a STH for the empty root
	root, err := signer.SignLogRoot(&types.LogRootV1{
		RootHash:       hasher.EmptyRoot(),
		TimestampNanos: uint64(timeSource.Now().UnixNano()),
	})
	if err != nil {
		return nil, err
	}

	// store the new STH
	err = logStorage.ReadWriteTransaction(context.Background(), tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		return tx.StoreSignedLogRoot(ctx, *root)
	})
	if err != nil {
		return nil, err
	}

	sequencer := log.NewSequencer(hasher, timeSource, logStorage, signer, nil, quota.Noop())

	return &testLog{
		tree: tree,
		root: root,

		key:    key,
		hasher: hasher,
		signer: signer,

		logStorage:   logStorage,
		adminStorage: adminStorage,
		sequencer:    sequencer,
	}, nil
}

func (t *testLog) getSTH() (*ct.GetSTHResponse, error) {
	tx, err := t.logStorage.SnapshotForTree(context.Background(), t.tree)
	if err != nil {
		return nil, err
	}

	signedLogRoot, err := tx.LatestSignedLogRoot(context.Background())
	if err != nil {
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	sth := ct.SignedTreeHead{
		Version:   ct.V1,
		TreeSize:  uint64(signedLogRoot.TreeSize),
		Timestamp: uint64(signedLogRoot.TimestampNanos / 1000 / 1000),
	}
	copy(sth.SHA256RootHash[:], signedLogRoot.RootHash)

	sthBytes, err := ct.SerializeSTHSignatureInput(sth)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(sthBytes)
	signature, err := t.key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	sth.TreeHeadSignature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.SignatureAlgorithmFromPubKey(t.signer.Public()),
		},
		Signature: signature,
	}

	marshaledSig, err := cttls.Marshal(sth.TreeHeadSignature)
	if err != nil {
		return nil, err
	}

	return &ct.GetSTHResponse{
		TreeSize:          sth.TreeSize,
		SHA256RootHash:    sth.SHA256RootHash[:],
		Timestamp:         sth.Timestamp,
		TreeHeadSignature: marshaledSig,
	}, nil
}

func (t *testLog) addChain(req []string, precert bool) error {
	chain := make([]ct.ASN1Cert, len(req))
	for i, certBase64 := range req {
		b, err := base64.StdEncoding.DecodeString(certBase64)
		if err != nil {
			return err
		}
		chain[i] = ct.ASN1Cert{Data: b}
	}

	// Generate the internal leaf entry for the SCT
	entryType := ct.X509LogEntryType
	if precert {
		entryType = ct.PrecertLogEntryType
	}
	leaf, err := ct.MerkleTreeLeafFromRawChain(chain, entryType, 0)
	if err != nil {
		return err
	}

	fmt.Printf("The MerkleTreeLeaf is: %#v\n", leaf)
	fmt.Printf("The TimestampedEntry is: %#v\n", leaf.TimestampedEntry)
	fmt.Printf("The X509Entry is: %#v\n", leaf.TimestampedEntry.X509Entry)

	// TODO(@cpu): Should use a better prefix here for the logging done by
	// util.BuildLogLeaf. Maybe the bind addr? Pubkey?
	logPrefix := "ct-test-srv"
	logLeaf, err := util.BuildLogLeaf(logPrefix, *leaf, 0, chain[0], chain[1:], precert)
	if err != nil {
		fmt.Printf("Err: %#v\n", err)
		return err
	}
	fmt.Printf("The LogLeaf is: %#v\n", logLeaf)

	leafHash, err := t.hasher.HashLeaf(logLeaf.LeafValue)
	if err != nil {
		return err
	}
	fmt.Printf("The LogLeaf hash is: %#v\n", leafHash)

	leaves := []*trillian.LogLeaf{&logLeaf}
	fmt.Printf("Leaves: %#v\n", leaves)

	resp, err := t.logStorage.QueueLeaves(context.Background(), t.tree, leaves, timeSource.Now())
	if err != nil {
		return err
	}
	fmt.Printf("QueueLeaves resp: %#v\n", resp)

	maxRootDuration, err := ptypes.Duration(t.tree.MaxRootDuration)
	if err != nil {
		return err
	}
	integratedCount, err := t.sequencer.IntegrateBatch(context.Background(), t.tree, 50, time.Duration(0), maxRootDuration)
	if err != nil {
		return err
	}
	fmt.Printf("integrated %d leaves\n", integratedCount)
	return nil
}
