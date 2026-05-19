from fastapi import APIRouter, HTTPException, Depends, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import logging
import hashlib
import time
from datetime import datetime, timedelta

# Import database and models
from database.connection import get_database_connection, close_database_connection
from models.user import LoginRequest, User, UserCreate, UserUpdate, UserPasswordUpdate
from models.mfa import MfaVerifyRequest
from utils.activity_log import log_user_activity
from auth_middleware import get_current_user_from_token
from services import mfa_service

# Rate limiting temporarily disabled

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)

MFA_PENDING_TTL_SECONDS = 300  # 5 minutes — pre-verification challenge lifetime
MFA_PENDING_MAX_ATTEMPTS = 5  # invalidate token after this many wrong codes


async def _fetch_mfa_state(conn, user_id: int):
    """Return (mfa_enabled, mfa_secret_encrypted, mfa_last_used_totp_step) or None
    when the MFA columns aren't yet present (pre-migration deploys).
    """
    try:
        return await conn.fetchrow(
            """
            SELECT mfa_enabled, mfa_secret_encrypted, mfa_last_used_totp_step
              FROM users
             WHERE id = $1
            """,
            user_id,
        )
    except Exception as exc:
        logger.warning(f"MFA columns not available (assuming disabled): {exc}")
        return None


async def _cleanup_expired_pending_logins(conn, user_id: int) -> None:
    """Lazy cleanup of expired pending MFA challenges for this user."""
    try:
        await conn.execute(
            "DELETE FROM mfa_pending_logins WHERE user_id = $1 AND expires_at < NOW()",
            user_id,
        )
    except Exception as exc:
        logger.debug(f"Pending-login cleanup skipped: {exc}")

# Security scheme
security = HTTPBearer()

@router.post("/login", summary="User Login", response_description="JWT access token and user information")
async def login(login_request: LoginRequest, request: Request):
    """
    # User Login - Authenticate and Get Access Token
    
    Authenticate user with username and password. Returns a JWT access token valid for 24 hours.
    
    ## Request Body
    - **username**: User's username (required)
    - **password**: User's password (required)
    
    ## Response
    Returns JWT token, user information, roles, and permissions.
    
    ## Example Request
    ```bash
    curl -X POST "{BASE_URL}/api/auth/login" \\
      -H "Content-Type: application/json" \\
      -d '{
        "username": "admin",
        "password": "admin123"
      }'
    ```
    
    > Replace `{BASE_URL}` with your deployment URL
    
    ## Example Response
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "bearer",
      "expires_in": 86400,
      "user": {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "role": "admin",
        "is_active": true,
        "created_at": "2024-01-01T00:00:00",
        "last_login_at": "2024-01-15T10:30:00"
      },
      "roles": [
        {
          "id": 1,
          "name": "admin",
          "display_name": "Administrator"
        }
      ],
      "permissions": {
        "clusters": {"read": true, "write": true, "delete": true},
        "agents": {"read": true, "write": true, "delete": true}
      }
    }
    ```
    
    ## Using the Token
    Include the access token in subsequent requests:
    ```bash
    curl -X GET "{BASE_URL}/api/clusters" \\
      -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    ```
    
    ## Error Responses
    - **401**: Invalid credentials or inactive account
    - **500**: Server error during authentication
    """
    
    try:
        conn = await get_database_connection()
        
        # Find user by username (with safe column handling)
        try:
            user = await conn.fetchrow("""
                SELECT id, username, email, password_hash, is_active, role, 
                       created_at, updated_at, last_login_at
                FROM users 
                WHERE username = $1 AND is_active = TRUE
            """, login_request.username)
        except Exception as schema_error:
            logger.warning(f"Schema error, trying fallback query: {schema_error}")
            # Fallback query without role column - try different column names
            try:
                user = await conn.fetchrow("""
                    SELECT id, username, email, password_hash, is_active,
                           created_at, updated_at, last_login_at
                    FROM users 
                    WHERE username = $1 AND is_active = TRUE
                """, login_request.username)
            except Exception as column_error:
                logger.warning(f"last_login_at column error, trying last_login: {column_error}")
                # Try with last_login instead of last_login_at
                user = await conn.fetchrow("""
                    SELECT id, username, email, password_hash, is_active,
                           created_at, updated_at, last_login
                    FROM users 
                    WHERE username = $1 AND is_active = TRUE
                """, login_request.username)
        
        if not user:
            # Covers both "no such user" and "soft-deleted (is_active=FALSE)".
            # We deliberately return the same generic 401 in either case to
            # avoid leaking whether an account exists (account enumeration
            # prevention). Soft-deleted rows are filtered out by the
            # `AND is_active = TRUE` predicate above.
            await close_database_connection(conn)
            logger.warning(f"Failed login attempt for username: {login_request.username}")
            raise HTTPException(status_code=401, detail="Invalid username or password")

        # Verify password
        import bcrypt
        if not bcrypt.checkpw(login_request.password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            await close_database_connection(conn)
            logger.warning(f"Wrong password for user: {login_request.username}")
            raise HTTPException(status_code=401, detail="Invalid username or password")

        # Issue #18 — MFA branch (v1.6.0): if the user opted in, defer JWT mint and
        # last_login update until /api/auth/login/mfa-verify completes.
        mfa_state = await _fetch_mfa_state(conn, user['id'])
        if mfa_state and mfa_state.get('mfa_enabled'):
            await _cleanup_expired_pending_logins(conn, user['id'])
            challenge_token = mfa_service.generate_challenge_token()
            try:
                await conn.execute(
                    """
                    INSERT INTO mfa_pending_logins (user_id, challenge_token, expires_at, ip_address)
                    VALUES ($1, $2, NOW() + ($3 || ' seconds')::interval, $4)
                    """,
                    user['id'],
                    challenge_token,
                    str(MFA_PENDING_TTL_SECONDS),
                    str(request.client.host) if request.client else None,
                )
            except Exception as exc:
                await close_database_connection(conn)
                logger.error(f"Failed to create MFA pending login: {exc}")
                raise HTTPException(status_code=500, detail="MFA challenge creation failed")

            await close_database_connection(conn)

            await log_user_activity(
                user_id=user['id'],
                action='mfa.login.challenge_issued',
                resource_type='mfa',
                resource_id=str(user['id']),
                details={'login_method': 'username_password'},
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent'),
            )

            return {
                "mfa_required": True,
                "mfa_token": challenge_token,
                "methods": ["totp", "backup"],
                "expires_in": MFA_PENDING_TTL_SECONDS,
            }

        # Update last login (try different column names)
        try:
            await conn.execute("""
                UPDATE users SET last_login_at = CURRENT_TIMESTAMP 
                WHERE id = $1
            """, user['id'])
        except Exception as update_error:
            logger.warning(f"last_login_at update failed, trying last_login: {update_error}")
            try:
                await conn.execute("""
                    UPDATE users SET last_login = CURRENT_TIMESTAMP 
                    WHERE id = $1
                """, user['id'])
            except Exception as fallback_error:
                logger.warning(f"Could not update last login: {fallback_error}")
                # Continue without updating last_login
        
        # Get user roles and permissions before closing connection
        conn_for_roles = conn
        
        # Fetch user roles with their permissions
        user_roles = await conn_for_roles.fetch("""
            SELECT r.id, r.name, r.display_name, r.permissions
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND ur.is_active = TRUE AND r.is_active = TRUE
        """, user['id'])
        
        # Build permissions dictionary
        permissions = {}
        roles_list = []
        
        for role_row in user_roles:
            roles_list.append({
                'id': role_row['id'],
                'name': role_row['name'],
                'display_name': role_row['display_name']
            })
            
            # Parse permissions from JSON string if needed
            role_permissions = role_row['permissions']
            if isinstance(role_permissions, str):
                import json
                role_permissions = json.loads(role_permissions)
            
            # Merge permissions (resource.action format)
            if role_permissions:
                for perm in role_permissions:
                    if '.' in perm:
                        resource, action = perm.split('.', 1)
                        if resource not in permissions:
                            permissions[resource] = {}
                        permissions[resource][action] = True
        
        await close_database_connection(conn)
        
        # Create JWT token
        from jose import jwt
        from config import JWT_SECRET_KEY, JWT_ALGORITHM
        
        payload = {
            "user_id": user['id'],
            "username": user['username'],
            "email": user.get('email'),
            "role": user.get('role', 'admin'),  # Default to admin if role column doesn't exist
            "exp": datetime.utcnow() + timedelta(hours=24)  # 24 hour expiry
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        # Log login activity
        await log_user_activity(
            user_id=user['id'],
            action='login',
            resource_type='auth',
            resource_id=str(user['id']),
            details={
                'login_method': 'username_password',
                'success': True
            },
            ip_address=str(request.client.host) if request.client else None,
            user_agent=request.headers.get('user-agent')
        )
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 86400,  # 24 hours in seconds
            "user": {
                "id": user['id'],
                "username": user['username'],
                "email": user.get('email'),
                "role": user.get('role', 'admin'),
                "is_active": user.get('is_active', True),
                "created_at": user['created_at'].isoformat() if user.get('created_at') else None,
                "last_login_at": datetime.utcnow().isoformat()
            },
            "roles": roles_list,
            "permissions": permissions
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@router.post(
    "/login/mfa-verify",
    summary="MFA Verification (Step 2 of Login)",
    response_description="JWT access token after successful TOTP/backup verification",
)
async def login_mfa_verify(payload: MfaVerifyRequest, request: Request):
    """
    # MFA Verification — Step 2 of the two-step login flow

    Submit a 6-digit TOTP code OR an 8-character backup code (with optional dash)
    together with the ``mfa_token`` returned by ``POST /api/auth/login`` for an
    MFA-enabled account. On success, returns the same response shape as a
    non-MFA login (Branch A).

    ## Request Body
    - **mfa_token**: 64-char challenge token from /login response
    - **code**: 6 digits (TOTP) or `XXXX-YYYY` (backup)

    ## Error Responses
    - **401**: Invalid code (attempts counter increments)
    - **410**: Challenge expired or invalidated (too many wrong attempts)
    """
    ip_address = str(request.client.host) if request.client else None
    user_agent = request.headers.get('user-agent')

    # Outcome captured from the transactional block so we can do JWT mint /
    # activity logging AFTER commit (no side effects on rollback).
    success_payload: Optional[dict] = None
    failure: Optional[dict] = None  # { user_id, attempts, invalidated, reason, http_status, detail }

    conn = None
    try:
        conn = await get_database_connection()

        # Round 1 audit fix — wrap the whole verify+update in a single
        # transaction with row-level locks (FOR UPDATE) so two concurrent
        # /mfa-verify calls cannot both consume the same TOTP step or the
        # same pending challenge. We never raise inside the transaction once
        # we've started mutating the pending row (would rollback the mark);
        # instead we capture `failure` and raise after commit.
        async with conn.transaction():
            pending = await conn.fetchrow(
                """
                SELECT id, user_id, attempts, expires_at, used_at
                  FROM mfa_pending_logins
                 WHERE challenge_token = $1
                 FOR UPDATE
                """,
                payload.mfa_token,
            )

            if not pending:
                failure = {
                    'user_id': None,
                    'attempts': 0,
                    'invalidated': True,
                    'reason': 'challenge_not_found',
                    'http_status': 410,
                    'detail': 'MFA challenge not found or expired',
                }
            elif pending['used_at'] is not None:
                failure = {
                    'user_id': pending['user_id'],
                    'attempts': pending['attempts'],
                    'invalidated': True,
                    'reason': 'challenge_already_used',
                    'http_status': 410,
                    'detail': 'MFA challenge already used',
                }
            elif pending['expires_at'] and pending['expires_at'] < datetime.utcnow():
                failure = {
                    'user_id': pending['user_id'],
                    'attempts': pending['attempts'],
                    'invalidated': True,
                    'reason': 'challenge_expired',
                    'http_status': 410,
                    'detail': 'MFA challenge expired',
                }
            elif pending['attempts'] >= MFA_PENDING_MAX_ATTEMPTS:
                await conn.execute(
                    "UPDATE mfa_pending_logins SET used_at = NOW() WHERE id = $1",
                    pending['id'],
                )
                failure = {
                    'user_id': pending['user_id'],
                    'attempts': pending['attempts'],
                    'invalidated': True,
                    'reason': 'too_many_attempts_pre_check',
                    'http_status': 410,
                    'detail': 'MFA challenge invalidated (too many attempts)',
                }

            if failure is None:
                # Lock the user row so the atomic TOTP-step bump cannot race a
                # parallel verify on a different pending challenge for the
                # same account.
                user_row = await conn.fetchrow(
                    """
                    SELECT id, username, email, role, is_active,
                           created_at, updated_at, last_login_at,
                           mfa_secret_encrypted, mfa_last_used_totp_step
                      FROM users
                     WHERE id = $1
                     FOR UPDATE
                    """,
                    pending['user_id'],
                )
                if not user_row or not user_row['is_active']:
                    failure = {
                        'user_id': pending['user_id'],
                        'attempts': pending['attempts'],
                        'invalidated': False,
                        'reason': 'user_unavailable',
                        'http_status': 401,
                        'detail': 'User not available',
                    }
                elif not user_row['mfa_secret_encrypted']:
                    failure = {
                        'user_id': user_row['id'],
                        'attempts': pending['attempts'],
                        'invalidated': True,
                        'reason': 'mfa_not_configured',
                        'http_status': 410,
                        'detail': 'MFA not configured for this user',
                    }
                else:
                    secret_plain = mfa_service.decrypt_secret(user_row['mfa_secret_encrypted'])
                    verified_method: Optional[str] = None
                    codes_remaining: Optional[int] = None

                    if secret_plain:
                        ok, step = mfa_service.verify_totp_with_replay_guard(
                            secret_plain, payload.code, user_row['mfa_last_used_totp_step']
                        )
                        if ok:
                            # Atomic step bump — refuse if another request already
                            # consumed this (or a newer) TOTP step.
                            bumped = await conn.fetchval(
                                """
                                UPDATE users
                                   SET mfa_last_used_totp_step = $1,
                                       mfa_last_used_at = NOW()
                                 WHERE id = $2
                                   AND (mfa_last_used_totp_step IS NULL
                                        OR mfa_last_used_totp_step < $1)
                                 RETURNING id
                                """,
                                step,
                                user_row['id'],
                            )
                            if bumped:
                                verified_method = 'totp'

                    if verified_method is None:
                        # Backup codes — atomic single-use consumption.
                        rows = await conn.fetch(
                            """
                            SELECT id, code_hash FROM mfa_backup_codes
                             WHERE user_id = $1 AND used_at IS NULL
                            """,
                            user_row['id'],
                        )
                        for row in rows:
                            if await mfa_service.check_backup_code(payload.code, row['code_hash']):
                                consumed_id = await conn.fetchval(
                                    """
                                    UPDATE mfa_backup_codes
                                       SET used_at = NOW()
                                     WHERE id = $1 AND used_at IS NULL
                                     RETURNING id
                                    """,
                                    row['id'],
                                )
                                if consumed_id:
                                    verified_method = 'backup'
                                    codes_remaining = await conn.fetchval(
                                        "SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL",
                                        user_row['id'],
                                    )
                                break

                    if verified_method is None:
                        new_attempts = pending['attempts'] + 1
                        invalidated = new_attempts >= MFA_PENDING_MAX_ATTEMPTS
                        await conn.execute(
                            """
                            UPDATE mfa_pending_logins
                               SET attempts = $1,
                                   used_at = CASE WHEN $2 THEN NOW() ELSE used_at END
                             WHERE id = $3
                            """,
                            new_attempts,
                            invalidated,
                            pending['id'],
                        )
                        failure = {
                            'user_id': user_row['id'],
                            'attempts': new_attempts,
                            'invalidated': invalidated,
                            'reason': 'invalid_code',
                            'http_status': 410 if invalidated else 401,
                            'detail': 'MFA challenge invalidated (too many attempts)'
                            if invalidated else 'Invalid MFA code',
                        }
                    else:
                        # Verified — finalize state inside the transaction so a
                        # concurrent verify sees used_at on retry.
                        await conn.execute(
                            "UPDATE mfa_pending_logins SET used_at = NOW() WHERE id = $1",
                            pending['id'],
                        )
                        if verified_method != 'totp':
                            await conn.execute(
                                "UPDATE users SET mfa_last_used_at = NOW() WHERE id = $1",
                                user_row['id'],
                            )
                        try:
                            await conn.execute(
                                "UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = $1",
                                user_row['id'],
                            )
                        except Exception as exc:
                            logger.warning(f"last_login_at update failed (continuing): {exc}")

                        user_roles = await conn.fetch(
                            """
                            SELECT r.id, r.name, r.display_name, r.permissions
                              FROM user_roles ur
                              JOIN roles r ON ur.role_id = r.id
                             WHERE ur.user_id = $1 AND ur.is_active = TRUE AND r.is_active = TRUE
                            """,
                            user_row['id'],
                        )

                        permissions: dict = {}
                        roles_list: list = []
                        for role_row in user_roles:
                            roles_list.append({
                                'id': role_row['id'],
                                'name': role_row['name'],
                                'display_name': role_row['display_name'],
                            })
                            role_permissions = role_row['permissions']
                            if isinstance(role_permissions, str):
                                import json
                                role_permissions = json.loads(role_permissions)
                            if role_permissions:
                                for perm in role_permissions:
                                    if '.' in perm:
                                        resource, action = perm.split('.', 1)
                                        if resource not in permissions:
                                            permissions[resource] = {}
                                        permissions[resource][action] = True

                        success_payload = {
                            'user': dict(user_row),
                            'roles_list': roles_list,
                            'permissions': permissions,
                            'method': verified_method,
                            'codes_remaining': codes_remaining,
                        }

        # ------------------------------------------------------------------
        # Transaction has committed. Side-effects (JWT mint, audit log) below.
        # ------------------------------------------------------------------
        await close_database_connection(conn)
        conn = None

        if failure is not None:
            if failure['user_id'] is not None:
                await log_user_activity(
                    user_id=failure['user_id'],
                    action='mfa.login.failed',
                    resource_type='mfa',
                    resource_id=str(failure['user_id']),
                    details={
                        'reason': failure['reason'],
                        'attempts': failure['attempts'],
                        'invalidated': failure['invalidated'],
                    },
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
            raise HTTPException(status_code=failure['http_status'], detail=failure['detail'])

        # Success path
        assert success_payload is not None  # for type checkers; transaction guarantees this
        user_row = success_payload['user']

        from jose import jwt
        from config import JWT_SECRET_KEY, JWT_ALGORITHM

        token_payload = {
            "user_id": user_row['id'],
            "username": user_row['username'],
            "email": user_row['email'],
            "role": user_row['role'] if 'role' in user_row.keys() else 'admin',
            "exp": datetime.utcnow() + timedelta(hours=24),
        }
        token = jwt.encode(token_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        await log_user_activity(
            user_id=user_row['id'],
            action='mfa.login.success',
            resource_type='mfa',
            resource_id=str(user_row['id']),
            details={
                'method': success_payload['method'],
                'codes_remaining': success_payload['codes_remaining']
                if success_payload['method'] == 'backup' else None,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 86400,
            "user": {
                "id": user_row['id'],
                "username": user_row['username'],
                "email": user_row['email'],
                "role": user_row['role'] if 'role' in user_row.keys() else 'admin',
                "is_active": user_row['is_active'],
                "created_at": user_row['created_at'].isoformat() if user_row.get('created_at') else None,
                "last_login_at": datetime.utcnow().isoformat(),
            },
            "roles": success_payload['roles_list'],
            "permissions": success_payload['permissions'],
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"MFA verify error: {exc}")
        raise HTTPException(status_code=500, detail="MFA verification failed")
    finally:
        if conn is not None:
            await close_database_connection(conn)


@router.post("/logout", summary="User Logout", response_description="Logout confirmation")
async def logout(request: Request, authorization: str = Header(None)):
    """
    # User Logout
    
    Logout current user and log activity. Requires valid JWT token.
    
    ## Headers
    - **Authorization**: Bearer {access_token}
    
    ## Example Request
    ```bash
    curl -X POST "{BASE_URL}/api/auth/logout" \\
      -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    ```
    
    ## Example Response
    ```json
    {
      "message": "Logout successful"
    }
    ```
    """
    try:
        # Get current user for activity logging
        current_user = await get_current_user_from_token(authorization)
        
        if current_user and current_user.get('id'):
            # Log logout activity
            await log_user_activity(
                user_id=current_user['id'],
                action='logout',
                resource_type='auth',
                resource_id=str(current_user['id']),
                details={
                    'logout_method': 'manual'
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        return {"message": "Logout successful"}
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        # Still return success even if logging fails
        return {"message": "Logout successful"}

@router.get("/me", summary="Get Current User", response_description="Current user information")
async def get_current_user(authorization: str = Header(None)):
    """
    # Get Current User Information
    
    Get authenticated user's profile information. Requires valid JWT token.
    
    ## Headers
    - **Authorization**: Bearer {access_token}
    
    ## Example Request
    ```bash
    curl -X GET "{BASE_URL}/api/auth/me" \\
      -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    ```
    
    ## Example Response
    ```json
    {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin",
      "is_active": true,
      "created_at": "2024-01-01T00:00:00",
      "updated_at": "2024-01-15T10:30:00",
      "last_login_at": "2024-01-15T10:30:00"
    }
    ```
    """
    try:
        current_user = await get_current_user_from_token(authorization)
        
        if not current_user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        conn = await get_database_connection()
        
        # Get fresh user data (with safe column handling)
        try:
            user = await conn.fetchrow("""
                SELECT id, username, email, role, is_active, 
                       created_at, updated_at, last_login_at
                FROM users 
                WHERE id = $1
            """, current_user['id'])
        except Exception as schema_error:
            logger.warning(f"Schema error in /me endpoint, trying fallback: {schema_error}")
            # Fallback query without role column - try different column names
            try:
                user = await conn.fetchrow("""
                    SELECT id, username, email, is_active,
                           created_at, updated_at, last_login_at
                    FROM users 
                    WHERE id = $1
                """, current_user['id'])
            except Exception as column_error:
                logger.warning(f"last_login_at column error in /me, trying last_login: {column_error}")
                # Try with last_login instead of last_login_at
                user = await conn.fetchrow("""
                    SELECT id, username, email, is_active,
                           created_at, updated_at, last_login
                    FROM users 
                    WHERE id = $1
                """, current_user['id'])
        
        await close_database_connection(conn)
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return {
            "id": user['id'],
            "username": user['username'],
            "email": user.get('email'),
            "role": user.get('role', 'admin'),
            "is_active": user.get('is_active', True),
            "created_at": user['created_at'].isoformat() if user.get('created_at') else None,
            "updated_at": user['updated_at'].isoformat() if user.get('updated_at') else None,
            "last_login_at": (user.get('last_login_at') or user.get('last_login', None)).isoformat() if (user.get('last_login_at') or user.get('last_login')) else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get current user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user info")

@router.post("/change-password", summary="Change Password", response_description="Password change confirmation")
async def change_password(password_update: UserPasswordUpdate, request: Request, authorization: str = Header(None)):
    """
    # Change User Password
    
    Change authenticated user's password. Requires current password for verification.
    
    ## Headers
    - **Authorization**: Bearer {access_token}
    
    ## Request Body
    - **current_password**: Current password for verification
    - **new_password**: New password (min 8 characters recommended)
    
    ## Example Request
    ```bash
    curl -X POST "{BASE_URL}/api/auth/change-password" \\
      -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \\
      -H "Content-Type: application/json" \\
      -d '{
        "current_password": "admin123",
        "new_password": "newSecurePassword456"
      }'
    ```
    
    ## Example Response
    ```json
    {
      "message": "Password changed successfully"
    }
    ```
    
    ## Error Responses
    - **400**: Current password is incorrect
    - **401**: Not authenticated
    - **404**: User not found
    """
    try:
        current_user = await get_current_user_from_token(authorization)
        
        if not current_user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        conn = await get_database_connection()
        
        # Get current user data
        user = await conn.fetchrow("""
            SELECT id, password_hash FROM users WHERE id = $1
        """, current_user['id'])
        
        if not user:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="User not found")
        
        # Verify current password
        import bcrypt
        if not bcrypt.checkpw(password_update.current_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        
        # Hash new password
        new_password_hash = bcrypt.hashpw(password_update.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password
        await conn.execute("""
            UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $2
        """, new_password_hash, current_user['id'])
        
        await close_database_connection(conn)
        
        # Log password change activity
        await log_user_activity(
            user_id=current_user['id'],
            action='update',
            resource_type='user',
            resource_id=str(current_user['id']),
            details={
                'action': 'password_change',
                'success': True
            },
            ip_address=str(request.client.host) if request.client else None,
            user_agent=request.headers.get('user-agent')
        )
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Change password error: {e}")
        raise HTTPException(status_code=500, detail="Failed to change password")

@router.get("/validate-token", summary="Validate Token", response_description="Token validation result")
async def validate_token(authorization: str = Header(None)):
    """
    # Validate JWT Token
    
    Check if a JWT token is valid and not expired.
    
    ## Headers
    - **Authorization**: Bearer {access_token}
    
    ## Example Request
    ```bash
    curl -X GET "{BASE_URL}/api/auth/validate-token" \\
      -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    ```
    
    ## Example Response
    ```json
    {
      "valid": true,
      "user": {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "role": "admin"
      }
    }
    ```
    
    ## Error Responses
    - **401**: Invalid or expired token
    """
    try:
        current_user = await get_current_user_from_token(authorization)
        
        if not current_user:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        return {
            "valid": True,
            "user": {
                "id": current_user['id'],
                "username": current_user['username'],
                "email": current_user.get('email'),
                "role": current_user.get('role', 'admin')
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        raise HTTPException(status_code=401, detail="Token validation failed") 