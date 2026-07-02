package approval

import "context"

type Notifier interface {
	NotifyApprovalRequested(ctx context.Context, rec Record) error
}

type Service struct {
	Store    Store
	Notifier Notifier
}

func NewService(store Store, notifier Notifier) *Service {
	return &Service{Store: store, Notifier: notifier}
}

func (s *Service) Request(ctx context.Context, req Request) (Record, bool, error) {
	if s == nil || s.Store == nil {
		return Record{}, false, nil
	}
	rec, created, err := s.Store.Request(ctx, req)
	if err != nil {
		return Record{}, false, err
	}
	if created && s.Notifier != nil {
		if err := s.Notifier.NotifyApprovalRequested(ctx, rec); err != nil {
			return Record{}, false, err
		}
	}
	return rec, created, nil
}

func (s *Service) Get(ctx context.Context, approvalID string) (Record, error) {
	if s == nil || s.Store == nil {
		return Record{}, ErrNotFound
	}
	return s.Store.Get(ctx, approvalID)
}

func (s *Service) GetByDecision(ctx context.Context, decisionID string) (Record, error) {
	if s == nil || s.Store == nil {
		return Record{}, ErrNotFound
	}
	return s.Store.GetByDecision(ctx, decisionID)
}

func (s *Service) Review(ctx context.Context, input ReviewInput) (Record, error) {
	if s == nil || s.Store == nil {
		return Record{}, ErrNotFound
	}
	return s.Store.Review(ctx, input)
}

func (s *Service) SetGitHubCheckRunID(ctx context.Context, approvalID string, checkRunID int64) (Record, error) {
	if s == nil || s.Store == nil {
		return Record{}, ErrNotFound
	}
	return s.Store.SetGitHubCheckRunID(ctx, approvalID, checkRunID)
}
