"""
Session Management for CatNet Authentication

Provides secure session handling with:
    - Session creation and validation
    - Session storage (Redis-ready)
    - Session expiration
    - Concurrent session limits
    - Session activity tracking

    import hashlib
    import secrets
    from typing import Dict, Any, Optional, List, Set, Tuple
    from datetime import datetime, timedelta
    from dataclasses import dataclass, field
    import json
    import hmac


    @dataclass
    class Session:
        """Represents a user session"""
        """

        """Represents a user session"""

        session_id: str
        user_id: str
        username: str
        ip_address: str
        user_agent: str
        created_at: datetime
        last_activity: datetime
        expires_at: datetime
        roles: List[str] = field(default_factory=list)
        permissions: List[str] = field(default_factory=list)
        metadata: Dict[str, Any] = field(default_factory=dict)
        is_active: bool = True
        refresh_token: Optional[str] = None
        mfa_verified: bool = False
        auth_method: str = "password"  # password, oauth, saml, ssh


        class SessionManager:
            """
            Manages user sessions with security features"""

            def __init__(:):
            self,
            session_lifetime: int = 3600,  # 1 hour
            max_sessions_per_user: int = 5,
            require_mfa_for_sensitive: bool = True,
            session_secret: Optional[str] = None,
            ):
                """
                Initialize session manager
                Args:
                    session_lifetime: Session lifetime in seconds
                    max_sessions_per_user: Maximum concurrent sessions per user
                    require_mfa_for_sensitive: Require MFA for sensitive operations
                    session_secret: Secret for session ID generation"""
                    self.session_lifetime = session_lifetime
                    self.max_sessions_per_user = max_sessions_per_user
                    self.require_mfa_for_sensitive = require_mfa_for_sensitive
                    self.session_secret = session_secret or secrets.token_hex(32)

        # In production, use Redis for session storage
                    self.sessions: Dict[str, Session] = {}
                    self.user_sessions: Dict[str, Set[str]] = {}
                    self.revoked_sessions: Set[str] = set()

                    def create_session(:):
                    self,
                    user_id: str,
                    username: str,
                    ip_address: str,
                    user_agent: str,
                    roles: List[str] = None,
                    permissions: List[str] = None,
                    auth_method: str = "password",
                    mfa_verified: bool = False,
                    metadata: Dict[str, Any] = None,
                    ) -> Session:
                        """
                        Create a new session
                        Args:
                            user_id: User identifier
                            username: Username
                            ip_address: Client IP address
                            user_agent: Client user agent
                            roles: User roles
                            permissions: User permissions
                            auth_method: Authentication method used
                            mfa_verified: Whether MFA was verified
                            metadata: Additional session metadata
                            Returns:
                                Created session object"""
        # Clean up old sessions for user
                                self._cleanup_user_sessions(user_id)

        # Check session limit
                                if user_id in self.user_sessions:
                                    if len(self.user_sessions[user_id]) >= self.max_sessions_per_user:
                # Remove oldest session
                                        oldest_session_id = min()
                                        self.user_sessions[user_id],
                                        key=lambda sid: self.sessions[sid].created_at,
                                        )
                                        self.terminate_session(oldest_session_id)

        # Generate secure session ID
                                        session_id = self._generate_session_id(user_id, ip_address, user_agent)

        # Create session
                                        now = datetime.utcnow()
                                        session = Session()
                                        session_id=session_id,
                                        user_id=user_id,
                                        username=username,
                                        ip_address=ip_address,
                                        user_agent=user_agent,
                                        created_at=now,
                                        last_activity=now,
                                        expires_at=now + timedelta(seconds=self.session_lifetime),
                                        roles=roles or [],
                                        permissions=permissions or [],
                                        metadata=metadata or {},
                                        auth_method=auth_method,
                                        mfa_verified=mfa_verified,
                                        )

        # Store session
                                        self.sessions[session_id] = session

        # Track user sessions
                                        if user_id not in self.user_sessions:
                                            self.user_sessions[user_id] = set()
                                            self.user_sessions[user_id].add(session_id)

                                            return session

                                        def get_session(self, session_id: str) -> Optional[Session]:
                                            """
                                            Get session by ID
                                            Args:
                                                session_id: Session identifier
                                                Returns:
                                                    Session object or None"""
        # Check if revoked
                                                    if session_id in self.revoked_sessions:
                                                        return None

                                                    session = self.sessions.get(session_id)

                                                    if not session:
                                                        return None

        # Check expiration
                                                    if datetime.utcnow() > session.expires_at:
                                                        self.terminate_session(session_id)
                                                        return None

        # Check if active
                                                    if not session.is_active:
                                                        return None

                                                    return session

                                                def validate_session(:):
                                                self,
                                                session_id: str,
                                                ip_address: Optional[str] = None,
                                                user_agent: Optional[str] = None,
                                                ) -> Tuple[bool, Optional[str]]:
                                                    """
                                                    Validate a session
                                                    Args:
                                                        session_id: Session identifier
                                                        ip_address: Client IP for validation
                                                        user_agent: Client user agent for validation
                                                        Returns:
                                                            Tuple of (is_valid, error_message)"""
                                                            session = self.get_session(session_id)

                                                            if not session:
                                                                return False, "Session not found or expired"

        # Validate IP address if provided
                                                            if ip_address and session.ip_address != ip_address:
            # Log potential session hijacking attempt
                                                                self._log_security_event()
                                                                "session_hijack_attempt",
                                                                {}
                                                                "session_id": session_id,
                                                                "original_ip": session.ip_address,
                                                                "current_ip": ip_address,
                                                                },
                                                                )
                                                                return False, "IP address mismatch"

        # Validate user agent if provided
                                                            if user_agent and session.user_agent != user_agent:
            # User agent change might be legitimate (browser update)
            # Log but don't necessarily invalidate
                                                                self._log_security_event()
                                                                "user_agent_change",
                                                                {}
                                                                "session_id": session_id,
                                                                "original_ua": session.user_agent,
                                                                "current_ua": user_agent,
                                                                },
                                                                )

                                                                return True, None

                                                            def update_activity(self, session_id: str) -> bool:
                                                                """
                                                                Update session last activity time
                                                                Args:
                                                                    session_id: Session identifier
                                                                    Returns:
                                                                        Success status"""
                                                                        session = self.get_session(session_id)

                                                                        if not session:
                                                                            return False

                                                                        session.last_activity = datetime.utcnow()

        # Optionally extend expiration on activity
                                                                        session.expires_at = datetime.utcnow() + timedelta()
                                                                        seconds=self.session_lifetime
                                                                        )

                                                                        return True

                                                                    def extend_session(:):
                                                                    self, session_id: str, additional_time: Optional[int] = None
                                                                    ) -> bool:
                                                                        """
                                                                        Extend session expiration
                                                                        Args:
                                                                            session_id: Session identifier
                                                                            additional_time: Additional seconds to add (default: \)
                                                                            session_lifetime)
                                                                            Returns:
                                                                                Success status"""
                                                                                session = self.get_session(session_id)

                                                                                if not session:
                                                                                    return False

                                                                                additional_seconds = additional_time or self.session_lifetime
                                                                                session.expires_at = datetime.utcnow() + \
                                                                                timedelta(seconds=additional_seconds)

                                                                                return True

                                                                            def terminate_session(self, session_id: str) -> bool:
                                                                                """
                                                                                Terminate a session
                                                                                Args:
                                                                                    session_id: Session identifier
                                                                                    Returns:
                                                                                        Success status"""
                                                                                        if session_id not in self.sessions:
                                                                                            return False

                                                                                        session = self.sessions[session_id]

        # Mark as inactive
                                                                                        session.is_active = False

        # Add to revoked list
                                                                                        self.revoked_sessions.add(session_id)

        # Remove from user sessions
                                                                                        if session.user_id in self.user_sessions:
                                                                                            self.user_sessions[session.user_id].discard(session_id)

        # Remove from active sessions
                                                                                            del self.sessions[session_id]

                                                                                            return True

                                                                                        def terminate_user_sessions(self, user_id: str) -> int:
                                                                                            """
                                                                                            Terminate all sessions for a user
                                                                                            Args:
                                                                                                user_id: User identifier
                                                                                                Returns:
                                                                                                    Number of sessions terminated"""
                                                                                                    if user_id not in self.user_sessions:
                                                                                                        return 0

                                                                                                    session_ids = list(self.user_sessions[user_id])
                                                                                                    count = 0

                                                                                                    for session_id in session_ids:
                                                                                                        if self.terminate_session(session_id):
                                                                                                            count += 1

                                                                                                            return count

                                                                                                        def get_user_sessions(self, user_id: str) -> List[Session]:
                                                                                                            """
                                                                                                            Get all active sessions for a user
                                                                                                            Args:
                                                                                                                user_id: User identifier
                                                                                                                Returns:
                                                                                                                    List of active sessions"""
                                                                                                                    if user_id not in self.user_sessions:
                                                                                                                        return []

                                                                                                                    sessions = []
                                                                                                                    for session_id in list(self.user_sessions[user_id]):
                                                                                                                        session = self.get_session(session_id)
                                                                                                                        if session:
                                                                                                                            sessions.append(session)

                                                                                                                            return sessions

                                                                                                                        def requires_mfa(self, session_id: str, operation: str) -> bool:
                                                                                                                            """
                                                                                                                            Check if operation requires MFA
                                                                                                                            Args:
                                                                                                                                session_id: Session identifier
                                                                                                                                operation: Operation to perform
                                                                                                                                Returns:
                                                                                                                                    Whether MFA is required"""
                                                                                                                                    if not self.require_mfa_for_sensitive:
                                                                                                                                        return False

                                                                                                                                    session = self.get_session(session_id)
                                                                                                                                    if not session:
                                                                                                                                        return True

        # Sensitive operations always require MFA
                                                                                                                                    sensitive_operations = []
                                                                                                                                    "delete_device",
                                                                                                                                    "modify_credentials",
                                                                                                                                    "export_configs",
                                                                                                                                    "admin_action",
                                                                                                                                    ]

                                                                                                                                    if operation in sensitive_operations:
                                                                                                                                        return not session.mfa_verified

                                                                                                                                    return False

                                                                                                                                def cleanup_expired_sessions(self) -> int:
                                                                                                                                    """
                                                                                                                                    Clean up expired sessions
                                                                                                                                    Returns:
                                                                                                                                        Number of sessions cleaned"""
                                                                                                                                        now = datetime.utcnow()
                                                                                                                                        expired = []

                                                                                                                                        for session_id, session in self.sessions.items():
                                                                                                                                            if now > session.expires_at or not session.is_active:
                                                                                                                                                expired.append(session_id)

                                                                                                                                                for session_id in expired:
                                                                                                                                                    self.terminate_session(session_id)

                                                                                                                                                    return len(expired)

                                                                                                                                                def get_session_statistics(self) -> Dict[str, Any]:
                                                                                                                                                    """
                                                                                                                                                    Get session statistics
                                                                                                                                                    Returns:
                                                                                                                                                        Statistics dictionary"""
                                                                                                                                                        total_sessions = len(self.sessions)
                                                                                                                                                        total_users = len(self.user_sessions)

                                                                                                                                                        auth_methods = {}
                                                                                                                                                        for session in self.sessions.values():
                                                                                                                                                            auth_methods[session.auth_method] = ()
                                                                                                                                                            auth_methods.get(session.auth_method, 0) + 1
                                                                                                                                                            )

                                                                                                                                                            return {}
                                                                                                                                                        "total_sessions": total_sessions,
                                                                                                                                                        "total_users": total_users,
                                                                                                                                                        "revoked_sessions": len(self.revoked_sessions),
                                                                                                                                                        "auth_methods": auth_methods,
                                                                                                                                                        "average_sessions_per_user": total_sessions / total_users
                                                                                                                                                        if total_users > 0:
                                                                                                                                                            else 0,:
                                                                                                                                                                }

                                                                                                                                                                def _generate_session_id(:):
                                                                                                                                                                self, user_id: str, ip_address: str, user_agent: str
                                                                                                                                                                ) -> str:
                                                                                                                                                                    """
                                                                                                                                                                    Generate secure session ID
                                                                                                                                                                    Args:
                                                                                                                                                                        user_id: User identifier
                                                                                                                                                                        ip_address: Client IP
                                                                                                                                                                        user_agent: Client user agent
                                                                                                                                                                        Returns:
                                                                                                                                                                            Session ID"""
        # Combine entropy sources
                                                                                                                                                                            data = ()
                                                                                                                                                                            f"{user_id}:{ip_address}:{user_agent}:"
                                                                                                                                                                            f"{datetime.utcnow().isoformat()}:{secrets.token_hex(16)}"
                                                                                                                                                                            )

        # Create HMAC for integrity
                                                                                                                                                                            h = hmac.new()
                                                                                                                                                                            self.session_secret.encode(),
                                                                                                                                                                            data.encode(),
                                                                                                                                                                            hashlib.sha256
                                                                                                                                                                            )

                                                                                                                                                                            return h.hexdigest()

                                                                                                                                                                        def _cleanup_user_sessions(self, user_id: str) -> None:
                                                                                                                                                                            """
                                                                                                                                                                            Clean up expired sessions for a user
                                                                                                                                                                            Args:
                                                                                                                                                                                user_id: User identifier"""
                                                                                                                                                                                if user_id not in self.user_sessions:
                                                                                                                                                                                    return

                                                                                                                                                                                    expired = []
                                                                                                                                                                                    for session_id in self.user_sessions[user_id]:
                                                                                                                                                                                        session = self.sessions.get(session_id)
                                                                                                                                                                                        if not session or datetime.utcnow() > session.expires_at:
                                                                                                                                                                                            expired.append(session_id)

                                                                                                                                                                                            for session_id in expired:
                                                                                                                                                                                                self.terminate_session(session_id)

                                                                                                                                                                                                def _log_security_event(:):
                                                                                                                                                                                                self,
                                                                                                                                                                                                event_type: str,
                                                                                                                                                                                                details: Dict[str,]
                                                                                                                                                                                                Any]
                                                                                                                                                                                                ) -> None:
                                                                                                                                                                                                    """
                                                                                                                                                                                                    Log security events
                                                                                                                                                                                                    Args:
                                                                                                                                                                                                        event_type: Type of security event
                                                                                                                                                                                                        details: Event details"""
        # In production, send to SIEM or security logging system
                                                                                                                                                                                                        event = {}
                                                                                                                                                                                                        "timestamp": datetime.utcnow().isoformat(),
                                                                                                                                                                                                        "type": event_type,
                                                                                                                                                                                                        "details": details,
                                                                                                                                                                                                        }
        # Log event
                                                                                                                                                                                                        print(f"SECURITY EVENT: {json.dumps(event)}")


# Convenience functions
                                                                                                                                                                                                        _default_manager = None


                                                                                                                                                                                                        def get_session_manager() -> SessionManager:
                                                                                                                                                                                                            """Get default session manager instance"""
                                                                                                                                                                                                            global _default_manager
                                                                                                                                                                                                            if _default_manager is None:
                                                                                                                                                                                                                _default_manager = SessionManager()
                                                                                                                                                                                                                return _default_manager
