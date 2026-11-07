package firewallauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type ApprovalRequest struct {
	Actor  string `json:"actor"`
	Action Action `json:"action"`
	Scope  Scope  `json:"scope"`
	Digest string `json:"digest"`
}
type receiptKey struct{}

func WithReceipt(ctx context.Context, receipt string) context.Context {
	return context.WithValue(ctx, receiptKey{}, receipt)
}
func Receipt(ctx context.Context) string { s, _ := ctx.Value(receiptKey{}).(string); return s }

type Protected struct {
	Action Action `json:"action"`
	Scope  Scope  `json:"scope"`
}
type approvalClaims struct {
	jwt.Claims
	Request  ApprovalRequest `json:"request"`
	Approver string          `json:"approver"`
}

// ReplayStore must atomically persist a unique receipt ID before returning.
// A failed operation may burn a receipt; it must never make a receipt reusable.
type ReplayStore interface {
	Consume(context.Context, string, time.Time) error
}

// SQLReplayStore uses an operator-owned SQLite database, not an in-memory map.
type SQLReplayStore struct{ DB *sql.DB }

func NewSQLReplayStore(ctx context.Context, db *sql.DB) (*SQLReplayStore, error) {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS firewall_approval_replay(id TEXT PRIMARY KEY,expires INTEGER NOT NULL)`)
	return &SQLReplayStore{DB: db}, err
}
func (s *SQLReplayStore) Consume(ctx context.Context, id string, expiry time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM firewall_approval_replay WHERE expires < ?`, time.Now().Add(-time.Minute).Unix()); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM firewall_approval_replay`).Scan(&count); err != nil {
		return err
	}
	if count >= 4096 {
		return errors.New("approval replay capacity exhausted")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO firewall_approval_replay(id,expires) VALUES(?,?)`, id, expiry.Unix()); err != nil {
		return ErrForbidden
	}
	return tx.Commit()
}

type Approvals struct {
	key       ed25519.PrivateKey
	store     ReplayStore
	protected []Protected
}

func NewApprovals(key ed25519.PrivateKey, store ReplayStore, protected []Protected) (*Approvals, error) {
	if len(key) != ed25519.PrivateKeySize || store == nil || len(protected) > 128 {
		return nil, errors.New("approval signing key, durable replay store and bounded protection rules required")
	}
	for _, rule := range protected {
		if !validPrincipal(Principal{ID: "protection", Grants: []Grant{{Scope: rule.Scope, Actions: []Action{rule.Action}}}}) || rule.Action != Deploy && rule.Action != Rollback && rule.Action != Lease {
			return nil, errors.New("invalid high-impact protection rule")
		}
	}
	return &Approvals{key: append(ed25519.PrivateKey(nil), key...), store: store, protected: append([]Protected(nil), protected...)}, nil
}
func Digest(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func (a *Approvals) Issue(ctx context.Context, r ApprovalRequest) (string, error) {
	p, ok := FromContext(ctx)
	if !ok || p.ID == r.Actor || r.Actor == "" || len(r.Digest) != 64 || !p.Allows(Approve, r.Scope) || !p.Allows(r.Action, r.Scope) {
		return "", ErrForbidden
	}
	if _, err := hex.DecodeString(r.Digest); err != nil {
		return "", ErrForbidden
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	now := time.Now()
	c := approvalClaims{Claims: jwt.Claims{Issuer: "netcap-firewall", Audience: jwt.Audience{"firewall-approval"}, Subject: r.Actor, ID: hex.EncodeToString(id), IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(5 * time.Minute))}, Request: r, Approver: p.ID}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: a.key}, nil)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(c).Serialize()
}
func (a *Approvals) Check(ctx context.Context, action Action, scope Scope, digest, receipt string) error {
	return a.CheckTargets(ctx, action, scope, nil, digest, receipt)
}

// Fleet receipts bind the complete target/CAS set through digest. A matching
// protected target requires approval over the enclosing tenant/app scope.
func (a *Approvals) CheckTargets(ctx context.Context, action Action, scope Scope, targets []string, digest, receipt string) error {
	required := false
	if len(targets) == 0 {
		targets = []string{scope.Target}
	}
	for _, target := range targets {
		s := scope
		s.Target = target
		for _, rule := range a.protected {
			if (Principal{Grants: []Grant{{Scope: rule.Scope, Actions: []Action{rule.Action}}}}).Allows(action, s) {
				required = true
			}
		}
	}
	if !required {
		return nil
	}
	p, ok := FromContext(ctx)
	if !ok || len(receipt) > 8192 {
		return ErrForbidden
	}
	t, err := jwt.ParseSigned(receipt, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return ErrForbidden
	}
	var c approvalClaims
	if t.Claims(a.key.Public(), &c) != nil || c.Expiry == nil || c.IssuedAt == nil || c.ID == "" || c.Approver == "" || c.Approver == p.ID || c.Subject != p.ID || c.Request != (ApprovalRequest{Actor: p.ID, Action: action, Scope: scope, Digest: digest}) {
		return ErrForbidden
	}
	if c.Expiry.Time().Sub(c.IssuedAt.Time()) > 5*time.Minute || c.ValidateWithLeeway(jwt.Expected{Issuer: "netcap-firewall", AnyAudience: jwt.Audience{"firewall-approval"}, Time: time.Now()}, 0) != nil {
		return ErrForbidden
	}
	return a.store.Consume(ctx, c.ID, c.Expiry.Time())
}
