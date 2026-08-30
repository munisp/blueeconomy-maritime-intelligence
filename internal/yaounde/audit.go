package yaounde

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/envelope"
)

// Audit event types (mirrored by the yaounde_audit_log CHECK constraint).
const (
	AuditPeerRegistered      = "peer.registered"
	AuditPeerActivated       = "peer.activated"
	AuditPeerSuspended       = "peer.suspended"
	AuditPeerRevoked         = "peer.revoked"
	AuditReleaseDrafted      = "release.drafted"
	AuditReleaseApproved     = "release.approved"
	AuditReleaseDispatched   = "release.dispatched"
	AuditReleaseAcknowledged = "release.acknowledged"
	AuditReleaseFailed       = "release.failed"
	AuditReleaseWithdrawn    = "release.withdrawn"
	AuditReleaseRefused      = "release.refused"
	AuditInboundAdmitted     = "inbound.admitted"
	AuditInboundRejected     = "inbound.rejected"
	AuditPicturePrepared     = "picture.prepared"
	AuditPictureDispatched   = "picture.dispatched"
	AuditPictureFailed       = "picture.failed"
)

// genesisLabel seeds the hash chain.
const genesisLabel = "yaounde-audit-genesis-v1"

// GenesisHash is the prev_hash of the first audit entry.
func GenesisHash() string {
	digest := sha256.Sum256([]byte(genesisLabel))
	return "sha256:" + hex.EncodeToString(digest[:])
}

// ErrAuditChainBroken is returned when a hash-chain verification finds a
// modified, reordered or dropped entry.
var ErrAuditChainBroken = errors.New("yaounde audit hash chain verification failed")

// AuditEntry is one retained audit record.
type AuditEntry struct {
	Seq       int64          `json:"seq"`
	EventType string         `json:"event_type"`
	Actor     string         `json:"actor"`
	SubjectID string         `json:"subject_id"`
	Detail    map[string]any `json:"detail"`
	PrevHash  string         `json:"prev_hash"`
	EntryHash string         `json:"entry_hash"`
	CreatedAt time.Time      `json:"created_at"`
}

// auditPreimage is the canonical entry content the hash binds: every field
// except the hash itself. JSON field order is fixed by the struct so the
// encoding is deterministic.
type auditPreimage struct {
	EventType string         `json:"event_type"`
	Actor     string         `json:"actor"`
	SubjectID string         `json:"subject_id"`
	Detail    map[string]any `json:"detail"`
	PrevHash  string         `json:"prev_hash"`
	CreatedAt string         `json:"created_at"`
}

// EntryHash computes the chain hash of one entry content.
func EntryHash(eventType, actor, subjectID string, detail map[string]any, prevHash string, createdAt time.Time) (string, error) {
	if !digestPattern.MatchString(prevHash) {
		return "", errors.New("prev_hash must be a sha256 digest")
	}
	encoded, err := canonicalJSON(auditPreimage{
		EventType: eventType, Actor: actor, SubjectID: subjectID,
		Detail: detail, PrevHash: prevHash,
		CreatedAt: createdAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return "", fmt.Errorf("encode audit preimage: %w", err)
	}
	return envelope.DigestSHA256(encoded), nil
}

// appendAuditInTransaction inserts one hash-chained audit entry inside tx.
// The chain head is read FOR UPDATE inside the same transaction so a commit
// either extends the chain or rolls back atomically with the audited action.
func appendAuditInTransaction(ctx context.Context, tx pgx.Tx, eventType, actor, subjectID string, detail map[string]any) (AuditEntry, error) {
	if eventType == "" || actor == "" || subjectID == "" {
		return AuditEntry{}, errors.New("audit event_type, actor and subject_id are required")
	}
	if detail == nil {
		detail = map[string]any{}
	}
	var prevHash string
	err := tx.QueryRow(ctx, `SELECT entry_hash FROM yaounde_audit_log ORDER BY seq DESC LIMIT 1 FOR UPDATE`).Scan(&prevHash)
	if errors.Is(err, pgx.ErrNoRows) {
		prevHash = GenesisHash()
	} else if err != nil {
		return AuditEntry{}, fmt.Errorf("read audit chain head: %w", err)
	}
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	entryHash, err := EntryHash(eventType, actor, subjectID, detail, prevHash, createdAt)
	if err != nil {
		return AuditEntry{}, err
	}
	entry := AuditEntry{
		EventType: eventType, Actor: actor, SubjectID: subjectID, Detail: detail,
		PrevHash: prevHash, EntryHash: entryHash, CreatedAt: createdAt,
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO yaounde_audit_log (event_type, actor, subject_id, detail, prev_hash, entry_hash, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING seq`,
		eventType, actor, subjectID, detail, prevHash, entryHash, createdAt).Scan(&entry.Seq)
	if err != nil {
		return AuditEntry{}, fmt.Errorf("append audit entry: %w", err)
	}
	return entry, nil
}

// AppendAudit records one audit entry in its own transaction (used for
// refusals and denials that roll back the business mutation: the refusal
// itself must still be durable evidence).
func (store *Store) AppendAudit(ctx context.Context, eventType, actor, subjectID string, detail map[string]any) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin audit append: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := appendAuditInTransaction(ctx, tx, eventType, actor, subjectID, detail); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListAudit returns the audit entries created within [from, to) in chain
// order. Zero bounds disable the corresponding filter.
func (store *Store) ListAudit(ctx context.Context, from, to time.Time) ([]AuditEntry, error) {
	query := `SELECT seq, event_type, actor, subject_id, detail, prev_hash, entry_hash, created_at
		FROM yaounde_audit_log`
	var args []any
	var filters string
	if !from.IsZero() {
		args = append(args, from.UTC())
		filters += fmt.Sprintf(" created_at >= $%d", len(args))
	}
	if !to.IsZero() {
		args = append(args, to.UTC())
		if filters != "" {
			filters += " AND"
		}
		filters += fmt.Sprintf(" created_at < $%d", len(args))
	}
	if filters != "" {
		query += " WHERE" + filters
	}
	query += " ORDER BY seq"
	rows, err := store.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	defer rows.Close()
	entries := make([]AuditEntry, 0)
	for rows.Next() {
		var entry AuditEntry
		if err := rows.Scan(&entry.Seq, &entry.EventType, &entry.Actor, &entry.SubjectID,
			&entry.Detail, &entry.PrevHash, &entry.EntryHash, &entry.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit entries: %w", err)
	}
	return entries, nil
}

// VerifyAuditChain recomputes the full hash chain from genesis and requires
// a byte-exact match with the retained hashes: any modified, reordered or
// dropped entry fails verification. An empty ledger verifies (nothing to
// attest).
func VerifyAuditChain(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	rows, err := pool.Query(ctx, `SELECT seq, event_type, actor, subject_id, detail, prev_hash, entry_hash, created_at
		FROM yaounde_audit_log ORDER BY seq`)
	if err != nil {
		return 0, fmt.Errorf("read audit ledger: %w", err)
	}
	defer rows.Close()
	prevHash := GenesisHash()
	var previousSeq int64
	count := 0
	for rows.Next() {
		var entry AuditEntry
		if err := rows.Scan(&entry.Seq, &entry.EventType, &entry.Actor, &entry.SubjectID,
			&entry.Detail, &entry.PrevHash, &entry.EntryHash, &entry.CreatedAt); err != nil {
			return count, fmt.Errorf("scan audit entry: %w", err)
		}
		if count > 0 && entry.Seq <= previousSeq {
			return count, fmt.Errorf("%w: sequence regression at seq %d", ErrAuditChainBroken, entry.Seq)
		}
		if entry.PrevHash != prevHash {
			return count, fmt.Errorf("%w: entry seq %d prev_hash mismatch (dropped or reordered entry)", ErrAuditChainBroken, entry.Seq)
		}
		recomputed, err := EntryHash(entry.EventType, entry.Actor, entry.SubjectID, entry.Detail, entry.PrevHash, entry.CreatedAt)
		if err != nil {
			return count, err
		}
		if recomputed != entry.EntryHash {
			return count, fmt.Errorf("%w: entry seq %d content hash mismatch (modified entry)", ErrAuditChainBroken, entry.Seq)
		}
		prevHash = entry.EntryHash
		previousSeq = entry.Seq
		count++
	}
	if err := rows.Err(); err != nil {
		return count, fmt.Errorf("iterate audit ledger: %w", err)
	}
	return count, nil
}
