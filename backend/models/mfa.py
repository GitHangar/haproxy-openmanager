"""MFA-specific Pydantic models — Issue #18, v1.6.0.

Kept in a separate module so the existing User / UserUpdate contracts in
``backend/models/user.py`` stay byte-identical for backwards compatibility.
"""
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class MfaVerifyRequest(BaseModel):
    """Body of POST /api/auth/login/mfa-verify (pre-auth — no JWT)."""

    mfa_token: str = Field(..., min_length=64, max_length=64)
    # 6 digits for TOTP or 8 alphanumerics (with optional dash) for backup codes
    code: str = Field(..., min_length=6, max_length=10)


class MfaEnrollStartResponse(BaseModel):
    """Returned by POST /api/mfa/enroll/start."""

    secret: str
    otpauth_uri: str
    expires_in: int  # pending enrollment TTL in seconds


class MfaEnrollConfirmRequest(BaseModel):
    """Body of POST /api/mfa/enroll/confirm (TOTP only — backup codes not yet issued)."""

    code: str = Field(..., min_length=6, max_length=6)


class MfaEnrollConfirmResponse(BaseModel):
    enabled: bool
    backup_codes: List[str]
    method: Literal["totp"] = "totp"


class MfaDisableRequest(BaseModel):
    """Body of POST /api/mfa/disable — TOTP or backup."""

    code: str = Field(..., min_length=6, max_length=10)


class MfaRegenerateBackupRequest(BaseModel):
    """Body of POST /api/mfa/backup-codes/regenerate — TOTP only."""

    code: str = Field(..., min_length=6, max_length=6)


class MfaRegenerateBackupResponse(BaseModel):
    backup_codes: List[str]


class MfaAdminResetRequest(BaseModel):
    """Body of POST /api/mfa/admin-reset/{user_id}."""

    reason: str = Field(..., min_length=3, max_length=500)


class MfaAdminResetAllRequest(BaseModel):
    """Body of POST /api/mfa/admin-reset-all (emergency)."""

    confirm: Literal["RESET ALL MFA"]
    reason: str = Field(..., min_length=3, max_length=500)


class MfaStatusResponse(BaseModel):
    enabled: bool
    method: Optional[str] = None
    enrolled_at: Optional[str] = None
    last_used_at: Optional[str] = None
    backup_codes_remaining: int = 0
