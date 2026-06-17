-- Optional raw review notes for explicit break-glass/debug capture.
-- Default API behavior stores notes_fingerprint only.

ALTER TABLE action_decision_reviews
    ADD COLUMN IF NOT EXISTS notes_raw TEXT;
