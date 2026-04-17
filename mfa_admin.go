package goauth

import (
	"errors"
)

// AdminBeginTOTPEnrollment starts TOTP enrollment for a target user and records
// MFA_ENABLE_INIT in auth_log.
func (m *Manager) AdminBeginTOTPEnrollment(auditCtx AdminAuditContext) (*TOTPEnrollment, error) {
	enrollment, err := m.Users.BeginTOTPEnrollment(auditCtx.Target, m.cfg.MFAIssuer, m.mfaKey)
	if err != nil {
		return nil, err
	}
	m.AuditMFAAdminEvent(LogEventMFAEnableInit, auditCtx)
	return enrollment, nil
}

// AdminConfirmTOTPEnrollment verifies a pending enrollment code for a target
// user and records MFA_ENABLE_CONFIRM in auth_log.
func (m *Manager) AdminConfirmTOTPEnrollment(auditCtx AdminAuditContext, code string) error {
	verified, pending, err := m.Users.VerifyTOTPEnrollment(auditCtx.Target, code, m.mfaKey)
	if err != nil {
		return err
	}
	if !pending {
		return errMFANoPending
	}
	if !verified {
		return errMFAVerifyFailed
	}
	m.AuditMFAAdminEvent(LogEventMFAEnableConfirm, auditCtx)
	return nil
}

// AdminDisableMFA disables all MFA factors for a target user and records
// MFA_DISABLE in auth_log.
func (m *Manager) AdminDisableMFA(auditCtx AdminAuditContext) error {
	if err := m.Users.DisableMFA(auditCtx.Target); err != nil {
		return err
	}
	m.AuditMFAAdminEvent(LogEventMFADisable, auditCtx)
	return nil
}

// AdminResetMFA clears all MFA factors/challenges for a target user and records
// MFA_RESET in auth_log.
func (m *Manager) AdminResetMFA(auditCtx AdminAuditContext) error {
	if err := m.Users.ResetMFA(auditCtx.Target); err != nil {
		return err
	}
	m.AuditMFAAdminEvent(LogEventMFAReset, auditCtx)
	return nil
}

// AdminRotateRecoveryCodes rotates a target user's recovery codes and records
// MFA_RECOVERY_ROTATE in auth_log.
func (m *Manager) AdminRotateRecoveryCodes(auditCtx AdminAuditContext, count int) ([]string, error) {
	codes, err := m.Users.GenerateRecoveryCodes(auditCtx.Target, count)
	if err != nil {
		return nil, err
	}
	m.AuditMFAAdminEvent(LogEventMFARecoveryRotate, auditCtx)
	return codes, nil
}

var errMFAVerifyFailed = errors.New("goauth: mfa enrollment verification failed")
var errMFANoPending = errors.New("goauth: no pending mfa enrollment")
