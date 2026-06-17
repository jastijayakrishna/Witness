package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testFingerprint = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestInsertActionDecisionOutcome(t *testing.T) {
	createdAt := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	db := &fakeMoatDB{row: fakeRow{values: []any{int64(7), createdAt}}}
	store := NewMoatStore(db)

	outcome, err := store.InsertActionDecisionOutcome(context.Background(), sampleOutcome("decision-1"))
	if err != nil {
		t.Fatalf("insert outcome: %v", err)
	}
	if outcome.ID != 7 {
		t.Fatalf("id=%d want 7", outcome.ID)
	}
	if !outcome.CreatedAt.Equal(createdAt) {
		t.Fatalf("created_at=%s want %s", outcome.CreatedAt, createdAt)
	}
	if len(db.queries) != 1 {
		t.Fatalf("queries=%d want 1", len(db.queries))
	}
	if !strings.Contains(db.queries[0], "INSERT INTO action_decision_outcomes") {
		t.Fatalf("unexpected query: %s", db.queries[0])
	}
}

func TestInsertActionDecisionOutcomeRejectsDuplicateDecisionID(t *testing.T) {
	db := &fakeMoatDB{row: fakeRow{err: &pgconn.PgError{Code: "23505"}}}
	store := NewMoatStore(db)

	_, err := store.InsertActionDecisionOutcome(context.Background(), sampleOutcome("decision-1"))
	if !errors.Is(err, ErrDuplicateDecisionID) {
		t.Fatalf("err=%v want ErrDuplicateDecisionID", err)
	}
}

func TestGetActionDecisionOutcome(t *testing.T) {
	createdAt := time.Date(2026, 6, 5, 12, 30, 0, 0, time.UTC)
	db := &fakeMoatDB{row: fakeRow{values: outcomeRowValues(9, "decision-9", createdAt)}}
	store := NewMoatStore(db)

	outcome, err := store.GetActionDecisionOutcome(context.Background(), "proj-a", "decision-9")
	if err != nil {
		t.Fatalf("get outcome: %v", err)
	}
	if outcome.DecisionID != "decision-9" {
		t.Fatalf("decision_id=%q want decision-9", outcome.DecisionID)
	}
	if outcome.ArgsFingerprint != testFingerprint {
		t.Fatalf("args_fingerprint=%q want test hash", outcome.ArgsFingerprint)
	}
	if outcome.EstimatedCostUSD == nil || *outcome.EstimatedCostUSD != 0.12 {
		t.Fatalf("estimated cost=%v want 0.12", outcome.EstimatedCostUSD)
	}
	if outcome.EstimatedRiskPrevented == nil || *outcome.EstimatedRiskPrevented != 0.91 {
		t.Fatalf("estimated risk prevented=%v want 0.91", outcome.EstimatedRiskPrevented)
	}
	if outcome.Environment != "production" || outcome.RecipientType != "external_customer" || outcome.OperationType != "delete" {
		t.Fatalf("semantic fields not round-tripped: env=%q recipient=%q op=%q", outcome.Environment, outcome.RecipientType, outcome.OperationType)
	}
}

func TestInsertActionDecisionOutcomeRejectsInvalidSemanticFields(t *testing.T) {
	cases := map[string]func(*ActionDecisionOutcome){
		"environment":    func(o *ActionDecisionOutcome) { o.Environment = "prod-west-2" },
		"recipient_type": func(o *ActionDecisionOutcome) { o.RecipientType = "vip" },
		"operation_type": func(o *ActionDecisionOutcome) { o.OperationType = "frobnicate" },
	}
	for field, mutate := range cases {
		t.Run(field, func(t *testing.T) {
			db := &fakeMoatDB{row: fakeRow{values: []any{int64(1), time.Now()}}}
			outcome := sampleOutcome("decision-" + field)
			mutate(&outcome)

			_, err := NewMoatStore(db).InsertActionDecisionOutcome(context.Background(), outcome)
			if err == nil {
				t.Fatalf("expected invalid %s to be rejected", field)
			}
			if len(db.queries) != 0 {
				t.Fatalf("invalid %s should fail before query, got %d queries", field, len(db.queries))
			}
		})
	}
}

func TestInsertActionDecisionOutcomeAllowsEmptySemanticFields(t *testing.T) {
	db := &fakeMoatDB{row: fakeRow{values: []any{int64(1), time.Now()}}}
	outcome := sampleOutcome("decision-empty-semantic")
	outcome.Environment = ""
	outcome.RecipientType = ""
	outcome.OperationType = ""

	if _, err := NewMoatStore(db).InsertActionDecisionOutcome(context.Background(), outcome); err != nil {
		t.Fatalf("empty semantic fields should be allowed: %v", err)
	}
}

func TestSemanticCaptureMigrationDefinesColumns(t *testing.T) {
	migrationBytes, err := migrationFS.ReadFile("migrations/0003_semantic_capture_fields.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	migration := string(migrationBytes)
	for _, want := range []string{
		"ALTER TABLE action_decision_outcomes",
		"ADD COLUMN IF NOT EXISTS environment TEXT",
		"ADD COLUMN IF NOT EXISTS recipient_type TEXT",
		"ADD COLUMN IF NOT EXISTS operation_type TEXT",
	} {
		if !strings.Contains(migration, want) {
			t.Fatalf("migration missing %q", want)
		}
	}
}

func TestGetActionDecisionOutcomeByDecisionID(t *testing.T) {
	createdAt := time.Date(2026, 6, 5, 12, 45, 0, 0, time.UTC)
	db := &fakeMoatDB{row: fakeRow{values: outcomeRowValues(10, "decision-10", createdAt)}}
	store := NewMoatStore(db)

	outcome, err := store.GetActionDecisionOutcomeByDecisionID(context.Background(), "decision-10")
	if err != nil {
		t.Fatalf("get outcome by decision_id: %v", err)
	}
	if outcome.DecisionID != "decision-10" {
		t.Fatalf("decision_id=%q want decision-10", outcome.DecisionID)
	}
	if !strings.Contains(db.queries[0], "WHERE decision_id = $1") {
		t.Fatalf("query does not use decision_id lookup: %s", db.queries[0])
	}
}

func TestAddActionDecisionReview(t *testing.T) {
	reviewedAt := time.Date(2026, 6, 5, 13, 0, 0, 0, time.UTC)
	db := &fakeMoatDB{row: fakeRow{values: []any{int64(4), reviewedAt}}}
	store := NewMoatStore(db)

	review, err := store.AddActionDecisionReview(context.Background(), ActionDecisionReview{
		Project:               "proj-a",
		DecisionID:            "decision-1",
		Label:                 "true_positive",
		ReviewerSource:        "human",
		ReviewerRole:          "sre",
		NotesFingerprint:      testFingerprint,
		PolicyChangeSuggested: true,
	})
	if err != nil {
		t.Fatalf("add review: %v", err)
	}
	if review.ID != 4 {
		t.Fatalf("id=%d want 4", review.ID)
	}
	if !review.ReviewedAt.Equal(reviewedAt) {
		t.Fatalf("reviewed_at=%s want %s", review.ReviewedAt, reviewedAt)
	}
	if !strings.Contains(db.queries[0], "INSERT INTO action_decision_reviews") {
		t.Fatalf("unexpected query: %s", db.queries[0])
	}
}

func TestAddActionDecisionReviewAllowsAppendOnlyHistory(t *testing.T) {
	reviewedAt := time.Date(2026, 6, 5, 13, 30, 0, 0, time.UTC)
	db := &fakeMoatDB{row: fakeRow{values: []any{int64(4), reviewedAt}}}
	store := NewMoatStore(db)

	review := ActionDecisionReview{
		Project:          "proj-a",
		DecisionID:       "decision-1",
		Label:            "needs_review",
		ReviewerSource:   "api",
		ReviewerRole:     "developer",
		NotesFingerprint: testFingerprint,
	}
	if _, err := store.AddActionDecisionReview(context.Background(), review); err != nil {
		t.Fatalf("first review: %v", err)
	}
	if _, err := store.AddActionDecisionReview(context.Background(), review); err != nil {
		t.Fatalf("second review: %v", err)
	}
	if len(db.queries) != 2 {
		t.Fatalf("review inserts=%d want 2", len(db.queries))
	}
}

func TestListUnreviewedDecisions(t *testing.T) {
	createdAt := time.Date(2026, 6, 5, 14, 0, 0, 0, time.UTC)
	db := &fakeMoatDB{rows: &fakeRows{rows: []fakeRow{
		{values: outcomeRowValues(11, "decision-11", createdAt)},
	}}}
	store := NewMoatStore(db)

	outcomes, err := store.ListUnreviewedDecisions(context.Background(), "proj-a", 25)
	if err != nil {
		t.Fatalf("list unreviewed: %v", err)
	}
	if len(outcomes) != 1 {
		t.Fatalf("len=%d want 1", len(outcomes))
	}
	if outcomes[0].DecisionID != "decision-11" {
		t.Fatalf("decision_id=%q want decision-11", outcomes[0].DecisionID)
	}
	if !strings.Contains(db.queries[0], "NOT EXISTS") {
		t.Fatalf("list query should exclude reviewed decisions: %s", db.queries[0])
	}
}

func TestCountUnreviewedDecisions(t *testing.T) {
	db := &fakeMoatDB{row: fakeRow{values: []any{int64(3)}}}
	store := NewMoatStore(db)

	count, err := store.CountUnreviewedDecisions(context.Background())
	if err != nil {
		t.Fatalf("count unreviewed: %v", err)
	}
	if count != 3 {
		t.Fatalf("count=%d want 3", count)
	}
	if !strings.Contains(db.queries[0], "NOT EXISTS") || !strings.Contains(db.queries[0], "action_decision_reviews") {
		t.Fatalf("count query should exclude reviewed decisions: %s", db.queries[0])
	}
}

func TestListActionDecisionOutcomesForExport(t *testing.T) {
	createdAt := time.Date(2026, 6, 5, 14, 30, 0, 0, time.UTC)
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	row := append(outcomeRowValues(12, "decision-12", createdAt), sql.NullString{String: "true_positive", Valid: true})
	db := &fakeMoatDB{rows: &fakeRows{rows: []fakeRow{{values: row}}}}
	store := NewMoatStore(db)

	items, err := store.ListActionDecisionOutcomesForExport(context.Background(), "proj-a", since, true)
	if err != nil {
		t.Fatalf("list export outcomes: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("len=%d want 1", len(items))
	}
	if items[0].Outcome.DecisionID != "decision-12" || items[0].ReviewLabel != "true_positive" {
		t.Fatalf("item=%+v", items[0])
	}
	if !strings.Contains(db.queries[0], "LEFT JOIN LATERAL") {
		t.Fatalf("query should select latest review label: %s", db.queries[0])
	}
	if !strings.Contains(db.queries[0], "latest_review.label IS NOT NULL") {
		t.Fatalf("query should support reviewed-only filter: %s", db.queries[0])
	}
	if db.queryArgs[0][0] != "proj-a" || !db.queryArgs[0][1].(time.Time).Equal(since) || db.queryArgs[0][2] != true {
		t.Fatalf("query args=%v", db.queryArgs[0])
	}
}

func TestInsertPolicyLearningEvent(t *testing.T) {
	createdAt := time.Date(2026, 6, 5, 15, 0, 0, 0, time.UTC)
	db := &fakeMoatDB{row: fakeRow{values: []any{int64(5), createdAt}}}
	store := NewMoatStore(db)

	event, err := store.InsertPolicyLearningEvent(context.Background(), PolicyLearningEvent{
		Project:          "proj-a",
		SourceDecisionID: "decision-1",
		ToolTemplate:     "refund_payment",
		OldPolicyHash:    testFingerprint,
		NewPolicyHash:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ChangeType:       "duplicate_window_change",
		Reason:           "reviewed_false_positive",
	})
	if err != nil {
		t.Fatalf("insert policy learning event: %v", err)
	}
	if event.ID != 5 {
		t.Fatalf("id=%d want 5", event.ID)
	}
	if !strings.Contains(db.queries[0], "INSERT INTO policy_learning_events") {
		t.Fatalf("unexpected query: %s", db.queries[0])
	}
}

func TestDataMoatRejectsRawSensitiveFields(t *testing.T) {
	t.Run("raw args are not accepted", func(t *testing.T) {
		db := &fakeMoatDB{row: fakeRow{values: []any{int64(1), time.Now()}}}
		outcome := sampleOutcome("decision-raw")
		outcome.ArgsFingerprint = `{"email":"customer@example.com","amount":100}`

		_, err := NewMoatStore(db).InsertActionDecisionOutcome(context.Background(), outcome)
		if !errors.Is(err, ErrRawSensitiveData) {
			t.Fatalf("err=%v want ErrRawSensitiveData", err)
		}
		if len(db.queries) != 0 {
			t.Fatalf("raw payload should fail before query, got %d queries", len(db.queries))
		}
	})

	t.Run("raw review notes are not accepted", func(t *testing.T) {
		db := &fakeMoatDB{row: fakeRow{values: []any{int64(1), time.Now()}}}
		review := ActionDecisionReview{
			Project:          "proj-a",
			DecisionID:       "decision-1",
			Label:            "false_positive",
			ReviewerSource:   "human",
			NotesFingerprint: "refund was for customer@example.com",
		}

		_, err := NewMoatStore(db).AddActionDecisionReview(context.Background(), review)
		if !errors.Is(err, ErrRawSensitiveData) {
			t.Fatalf("err=%v want ErrRawSensitiveData", err)
		}
		if len(db.queries) != 0 {
			t.Fatalf("raw note should fail before query, got %d queries", len(db.queries))
		}
	})

	t.Run("raw args in evidence are not accepted", func(t *testing.T) {
		db := &fakeMoatDB{row: fakeRow{values: []any{int64(1), time.Now()}}}
		outcome := sampleOutcome("decision-evidence-raw")
		outcome.EvidenceJSON = []byte(`[{"args":{"email":"customer@example.com"}}]`)

		_, err := NewMoatStore(db).InsertActionDecisionOutcome(context.Background(), outcome)
		if !errors.Is(err, ErrRawSensitiveData) {
			t.Fatalf("err=%v want ErrRawSensitiveData", err)
		}
		if len(db.queries) != 0 {
			t.Fatalf("raw evidence should fail before query, got %d queries", len(db.queries))
		}
	})

	t.Run("obvious sensitive evidence keys are not accepted", func(t *testing.T) {
		for _, key := range []string{"password", "token", "api_key", "secret", "authorization", "email", "phone", "ssn", "credit_card", "card_number", "address"} {
			t.Run(key, func(t *testing.T) {
				db := &fakeMoatDB{row: fakeRow{values: []any{int64(1), time.Now()}}}
				outcome := sampleOutcome("decision-evidence-" + strings.ReplaceAll(key, "_", "-"))
				outcome.EvidenceJSON = []byte(fmt.Sprintf(`[{%q:"raw"}]`, key))

				_, err := NewMoatStore(db).InsertActionDecisionOutcome(context.Background(), outcome)
				if !errors.Is(err, ErrRawSensitiveData) {
					t.Fatalf("err=%v want ErrRawSensitiveData", err)
				}
				if len(db.queries) != 0 {
					t.Fatalf("sensitive evidence should fail before query, got %d queries", len(db.queries))
				}
			})
		}
	})
}

func TestDataMoatMigrationDefinesTablesAndIndexes(t *testing.T) {
	migrationBytes, err := migrationFS.ReadFile("migrations/0001_data_moat.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	migration := string(migrationBytes)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS action_decision_outcomes",
		"CREATE TABLE IF NOT EXISTS action_decision_reviews",
		"CREATE TABLE IF NOT EXISTS policy_learning_events",
		"decision_id              TEXT NOT NULL UNIQUE",
		"action_decision_outcomes_project_decision_unique",
		"fk_action_decision_reviews_outcome",
		"fk_policy_learning_events_outcome",
		"hubbleops_action           TEXT NOT NULL CHECK",
		"label                    TEXT NOT NULL CHECK",
		"reviewer_source          TEXT NOT NULL CHECK",
		"change_type              TEXT NOT NULL CHECK",
		"idx_action_decision_outcomes_project_created_at",
		"idx_action_decision_outcomes_project_action_name",
		"idx_action_decision_outcomes_project_result_class",
		"idx_action_decision_outcomes_project_hubbleops_action",
		"idx_action_decision_reviews_project_label",
		"idx_policy_learning_events_project_created_at",
	} {
		if !strings.Contains(migration, want) {
			t.Fatalf("migration missing %q", want)
		}
	}
}

func TestDecisionReviewRawNotesMigrationDefinesColumn(t *testing.T) {
	migrationBytes, err := migrationFS.ReadFile("migrations/0002_decision_review_raw_notes.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	migration := string(migrationBytes)
	for _, want := range []string{
		"ALTER TABLE action_decision_reviews",
		"ADD COLUMN IF NOT EXISTS notes_raw TEXT",
	} {
		if !strings.Contains(migration, want) {
			t.Fatalf("migration missing %q", want)
		}
	}
}

func TestDataMoatMigrationApplies(t *testing.T) {
	dsn := os.Getenv("HUBBLEOPS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set HUBBLEOPS_TEST_POSTGRES_DSN to run Postgres migration apply test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

func sampleOutcome(decisionID string) ActionDecisionOutcome {
	cost := 0.12
	riskPrevented := 0.91
	return ActionDecisionOutcome{
		Project:                "proj-a",
		SessionID:              "session-a",
		TrajectoryID:           "trajectory-a",
		DecisionID:             decisionID,
		ReceiptID:              "receipt-a",
		ActionName:             "refund_payment",
		ActionType:             "payment",
		ActionRisk:             "high",
		ToolSignatureHash:      testFingerprint,
		IdempotencyKeyHash:     testFingerprint,
		ResourceFingerprint:    testFingerprint,
		ArgsFingerprint:        testFingerprint,
		ResultFingerprint:      testFingerprint,
		ResultClass:            "blocked_duplicate",
		StateDeltaHash:         testFingerprint,
		HubbleOpsAction:          "block",
		DecisionReason:         "duplicate_side_effect",
		EvidenceJSON:           []byte(`[{"signal":"duplicate_side_effect"}]`),
		PolicyVersion:          "policy-v1",
		DetectorVersion:        "detector-v1",
		EstimatedCostUSD:       &cost,
		EstimatedRiskPrevented: &riskPrevented,
		Environment:            "production",
		RecipientType:          "external_customer",
		OperationType:          "delete",
	}
}

func outcomeRowValues(id int64, decisionID string, createdAt time.Time) []any {
	return []any{
		id,
		"proj-a",
		"session-a",
		sql.NullString{String: "trajectory-a", Valid: true},
		decisionID,
		sql.NullString{String: "receipt-a", Valid: true},
		"refund_payment",
		"payment",
		"high",
		sql.NullString{String: testFingerprint, Valid: true},
		sql.NullString{String: testFingerprint, Valid: true},
		sql.NullString{String: testFingerprint, Valid: true},
		sql.NullString{String: testFingerprint, Valid: true},
		sql.NullString{String: testFingerprint, Valid: true},
		"blocked_duplicate",
		sql.NullString{String: testFingerprint, Valid: true},
		"block",
		"duplicate_side_effect",
		[]byte(`[{"signal":"duplicate_side_effect"}]`),
		"policy-v1",
		"detector-v1",
		sql.NullFloat64{Float64: 0.12, Valid: true},
		sql.NullFloat64{Float64: 0.91, Valid: true},
		sql.NullString{String: "production", Valid: true},
		sql.NullString{String: "external_customer", Valid: true},
		sql.NullString{String: "delete", Valid: true},
		createdAt,
	}
}

type fakeMoatDB struct {
	row       fakeRow
	rows      *fakeRows
	queryErr  error
	execErr   error
	queries   []string
	queryArgs [][]any
}

func (db *fakeMoatDB) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	db.queries = append(db.queries, query)
	db.queryArgs = append(db.queryArgs, args)
	return pgconn.NewCommandTag("INSERT 0 1"), db.execErr
}

func (db *fakeMoatDB) Query(_ context.Context, query string, args ...any) (pgx.Rows, error) {
	db.queries = append(db.queries, query)
	db.queryArgs = append(db.queryArgs, args)
	if db.queryErr != nil {
		return nil, db.queryErr
	}
	if db.rows == nil {
		db.rows = &fakeRows{}
	}
	return db.rows, nil
}

func (db *fakeMoatDB) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	db.queries = append(db.queries, query)
	db.queryArgs = append(db.queryArgs, args)
	return db.row
}

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return fmt.Errorf("scan dest count=%d values=%d", len(dest), len(r.values))
	}
	for i := range dest {
		if err := assignScanValue(dest[i], r.values[i]); err != nil {
			return fmt.Errorf("scan column %d: %w", i, err)
		}
	}
	return nil
}

type fakeRows struct {
	rows   []fakeRow
	index  int
	closed bool
	err    error
}

func (r *fakeRows) Close() {
	r.closed = true
}

func (r *fakeRows) Err() error {
	return r.err
}

func (r *fakeRows) CommandTag() pgconn.CommandTag {
	return pgconn.NewCommandTag("SELECT 1")
}

func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}

func (r *fakeRows) Next() bool {
	if r.index >= len(r.rows) {
		r.closed = true
		return false
	}
	r.index++
	return true
}

func (r *fakeRows) Scan(dest ...any) error {
	if r.index == 0 || r.index > len(r.rows) {
		return fmt.Errorf("scan called without current row")
	}
	return r.rows[r.index-1].Scan(dest...)
}

func (r *fakeRows) Values() ([]any, error) {
	if r.index == 0 || r.index > len(r.rows) {
		return nil, fmt.Errorf("values called without current row")
	}
	return r.rows[r.index-1].values, nil
}

func (r *fakeRows) RawValues() [][]byte {
	return nil
}

func (r *fakeRows) Conn() *pgx.Conn {
	return nil
}

func assignScanValue(dest any, value any) error {
	switch d := dest.(type) {
	case *int:
		v, ok := value.(int)
		if !ok {
			return fmt.Errorf("cannot assign %T to *int", value)
		}
		*d = v
	case *int64:
		v, ok := value.(int64)
		if !ok {
			return fmt.Errorf("cannot assign %T to *int64", value)
		}
		*d = v
	case *string:
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("cannot assign %T to *string", value)
		}
		*d = v
	case *[]byte:
		switch v := value.(type) {
		case []byte:
			*d = append((*d)[:0], v...)
		case string:
			*d = []byte(v)
		default:
			return fmt.Errorf("cannot assign %T to *[]byte", value)
		}
	case *time.Time:
		v, ok := value.(time.Time)
		if !ok {
			return fmt.Errorf("cannot assign %T to *time.Time", value)
		}
		*d = v
	case *bool:
		v, ok := value.(bool)
		if !ok {
			return fmt.Errorf("cannot assign %T to *bool", value)
		}
		*d = v
	case *sql.NullString:
		switch v := value.(type) {
		case nil:
			*d = sql.NullString{}
		case string:
			*d = sql.NullString{String: v, Valid: true}
		case sql.NullString:
			*d = v
		default:
			return fmt.Errorf("cannot assign %T to *sql.NullString", value)
		}
	case *sql.NullFloat64:
		switch v := value.(type) {
		case nil:
			*d = sql.NullFloat64{}
		case float64:
			*d = sql.NullFloat64{Float64: v, Valid: true}
		case sql.NullFloat64:
			*d = v
		default:
			return fmt.Errorf("cannot assign %T to *sql.NullFloat64", value)
		}
	default:
		return fmt.Errorf("unsupported scan destination %T", dest)
	}
	return nil
}
