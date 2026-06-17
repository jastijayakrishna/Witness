package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrInvalidKey = errors.New("invalid api key")

type KeyStore interface {
	LookupAPIKey(ctx context.Context, rawKey string) (KeyRecord, error)
}

type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type PostgresKeyStore struct {
	db rowQuerier
}

func NewPostgresKeyStore(db rowQuerier) *PostgresKeyStore {
	return &PostgresKeyStore{db: db}
}

func (s *PostgresKeyStore) LookupAPIKey(ctx context.Context, rawKey string) (KeyRecord, error) {
	if strings.TrimSpace(rawKey) == "" {
		return KeyRecord{}, ErrInvalidKey
	}
	if s == nil || s.db == nil {
		return KeyRecord{}, fmt.Errorf("api key store unavailable")
	}

	var rec KeyRecord
	var expiresAt pgtype.Timestamptz
	err := s.db.QueryRow(ctx, `
SELECT p.slug, ak.disabled_at IS NOT NULL, ak.expires_at
FROM api_keys ak
JOIN projects p ON p.id = ak.project_id
WHERE ak.key_hash = $1 OR ak.key_hash = $2
LIMIT 1`,
		HashAPIKey(rawKey),
		legacyHashAPIKey(rawKey),
	).Scan(&rec.Project, &rec.Disabled, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return KeyRecord{}, ErrInvalidKey
	}
	if err != nil {
		return KeyRecord{}, err
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		rec.ExpiresAt = &t
	}
	return rec, nil
}
