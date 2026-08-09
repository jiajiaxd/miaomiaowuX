package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

const agentXrayConfigTransactionPath = "/api/child/xray/config-transaction"

type xrayConfigTransactionTarget struct {
	ServerID int64
	Config   string
}

type agentConfigTransactionResponse struct {
	Success    bool   `json:"success"`
	State      string `json:"state"`
	OldHash    string `json:"old_hash"`
	NewHash    string `json:"new_hash"`
	Message    string `json:"message"`
	RolledBack bool   `json:"rolled_back"`
}

func callAgentConfigTransaction(ctx context.Context, rm *RemoteManageHandler, serverID int64, operationID, action, config string) (*agentConfigTransactionResponse, error) {
	body, err := json.Marshal(map[string]string{
		"operation_id": operationID,
		"action":       action,
		"config":       config,
	})
	if err != nil {
		return nil, err
	}
	raw, err := rm.forwardToRemoteServer(ctx, serverID, "POST", agentXrayConfigTransactionPath, body)
	if err != nil {
		return nil, err
	}
	var resp agentConfigTransactionResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse %s response from server %d: %w", action, serverID, err)
	}
	if !resp.Success {
		if resp.Message == "" {
			resp.Message = "agent rejected operation"
		}
		return &resp, fmt.Errorf("server %d %s: %s", serverID, action, resp.Message)
	}
	return &resp, nil
}

// applyXrayConfigTransaction performs a coordinated prepare/activate across all
// affected Agents. No target is activated until every target has staged and
// validated its complete candidate. Any activation failure rolls every target
// back to the exact bytes captured during prepare.
func applyXrayConfigTransaction(ctx context.Context, rm *RemoteManageHandler, operationID string, targets []xrayConfigTransactionTarget) error {
	if len(targets) == 0 {
		return nil
	}
	if rm == nil {
		return errors.New("remote manager unavailable")
	}

	prepared := make(map[int64]bool, len(targets))
	var preparedMu sync.Mutex
	var prepareErrs []error
	var prepareErrsMu sync.Mutex
	var wg sync.WaitGroup
	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := callAgentConfigTransaction(ctx, rm, target.ServerID, operationID, "prepare", target.Config); err != nil {
				prepareErrsMu.Lock()
				prepareErrs = append(prepareErrs, err)
				prepareErrsMu.Unlock()
				return
			}
			preparedMu.Lock()
			prepared[target.ServerID] = true
			preparedMu.Unlock()
		}()
	}
	wg.Wait()
	if len(prepareErrs) > 0 {
		for serverID := range prepared {
			_, _ = callAgentConfigTransaction(context.WithoutCancel(ctx), rm, serverID, operationID, "abort", "")
		}
		return fmt.Errorf("prepare xray configuration transaction: %w", errors.Join(prepareErrs...))
	}

	var activateErrs []error
	var activateErrsMu sync.Mutex
	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := callAgentConfigTransaction(ctx, rm, target.ServerID, operationID, "activate", ""); err != nil {
				activateErrsMu.Lock()
				activateErrs = append(activateErrs, err)
				activateErrsMu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(activateErrs) == 0 {
		return nil
	}

	rollbackCtx := context.WithoutCancel(ctx)
	var rollbackErrs []error
	var rollbackErrsMu sync.Mutex
	for serverID := range prepared {
		serverID := serverID
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := callAgentConfigTransaction(rollbackCtx, rm, serverID, operationID, "rollback", ""); err != nil {
				rollbackErrsMu.Lock()
				rollbackErrs = append(rollbackErrs, err)
				rollbackErrsMu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(rollbackErrs) > 0 {
		return fmt.Errorf("activate failed (%v); rollback incomplete: %w", errors.Join(activateErrs...), errors.Join(rollbackErrs...))
	}
	return fmt.Errorf("activate xray configuration transaction failed and was rolled back: %w", errors.Join(activateErrs...))
}

func finishXrayConfigTransaction(ctx context.Context, rm *RemoteManageHandler, operationID string, targets []xrayConfigTransactionTarget, commit bool) error {
	action := "rollback"
	if commit {
		action = "commit"
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for _, target := range targets {
		serverID := target.ServerID
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := callAgentConfigTransaction(ctx, rm, serverID, operationID, action, ""); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}
