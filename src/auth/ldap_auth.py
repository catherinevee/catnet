"""
LDAP/Active Directory authentication module for CatNet
"""
import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, AUTO_BIND_NO_TLS
from ldap3.core.exceptions import LDAPException, LDAPBindError
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import asyncio
from ..core.config import settings
from ..core.exceptions import AuthenticationError, AuthorizationError
from ..db.models import User, Role
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

logger = logging.getLogger(__name__)


class LDAPAuthenticator:
    """LDAP/Active Directory authentication handler"""

    def __init__(self):
        self.server = None
        self.base_dn = settings.ldap_base_dn
        self.bind_dn = settings.ldap_bind_dn
        self.bind_password = settings.ldap_bind_password.get_secret_value() if settings.ldap_bind_password else None
        self.user_search_filter = "(|(sAMAccountName={username})(uid={username})(mail={username}))"
        self.group_search_filter = "(member={user_dn})"
        self.user_attributes = [
            'cn', 'displayName', 'mail', 'sAMAccountName', 'uid',
            'memberOf', 'userPrincipalName', 'givenName', 'sn',
            'title', 'department', 'telephoneNumber', 'mobile'
        ]
        self._connection_pool = []
        self._pool_size = 5
        self._initialize_server()

    def _initialize_server(self):
        """Initialize LDAP server connection"""
        if not settings.ldap_server:
            logger.warning("LDAP server not configured")
            return

        try:
            # Parse LDAP URL
            if settings.ldap_server.startswith('ldaps://'):
                use_ssl = True
                host = settings.ldap_server.replace('ldaps://', '')
                port = 636
            else:
                use_ssl = False
                host = settings.ldap_server.replace('ldap://', '')
                port = 389

            # Override port if specified
            if ':' in host:
                host, port_str = host.split(':')
                port = int(port_str)

            # Create server object
            self.server = Server(
                host,
                port=port,
                use_ssl=use_ssl,
                get_info=ALL,
                connect_timeout=10
            )

            logger.info(f"LDAP server initialized: {host}:{port} (SSL: {use_ssl})")

        except Exception as e:
            logger.error(f"Failed to initialize LDAP server: {e}")
            self.server = None

    async def _get_connection(self) -> Optional[Connection]:
        """Get LDAP connection from pool or create new one"""
        if not self.server:
            return None

        # Try to get connection from pool
        while self._connection_pool:
            conn = self._connection_pool.pop()
            if conn.bound:
                return conn
            else:
                try:
                    conn.unbind()
                except Exception as e:
                    logger.debug(f"Error unbinding LDAP connection: {e}")

        # Create new connection
        try:
            conn = await asyncio.get_event_loop().run_in_executor(
                None,
                self._create_connection
            )
            return conn
        except Exception as e:
            logger.error(f"Failed to create LDAP connection: {e}")
            return None

    def _create_connection(self) -> Connection:
        """Create new LDAP connection"""
        conn = Connection(
            self.server,
            user=self.bind_dn,
            password=self.bind_password,
            authentication=SIMPLE,
            auto_bind=AUTO_BIND_NO_TLS,
            raise_exceptions=True,
            pool_name='catnet_pool',
            pool_size=self._pool_size,
            pool_lifetime=3600
        )
        return conn

    async def _return_connection(self, conn: Connection):
        """Return connection to pool"""
        if conn and conn.bound and len(self._connection_pool) < self._pool_size:
            self._connection_pool.append(conn)
        else:
            try:
                conn.unbind()
            except Exception as e:
                logger.debug(f"Error unbinding LDAP connection during cleanup: {e}")

    async def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate user against LDAP

        Args:
            username: Username or email
            password: User password

        Returns:
            Dict containing user information from LDAP
        """
        if not self.server:
            raise AuthenticationError("LDAP authentication not available")

        conn = await self._get_connection()
        if not conn:
            raise AuthenticationError("Failed to connect to LDAP server")

        try:
            # Search for user
            search_filter = self.user_search_filter.format(username=username)

            await asyncio.get_event_loop().run_in_executor(
                None,
                conn.search,
                self.base_dn,
                search_filter,
                attributes=self.user_attributes
            )

            if not conn.entries:
                raise AuthenticationError(f"User {username} not found in LDAP")

            user_entry = conn.entries[0]
            user_dn = user_entry.entry_dn

            # Attempt to bind with user credentials
            user_conn = None
            try:
                user_conn = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: Connection(
                        self.server,
                        user=user_dn,
                        password=password,
                        authentication=SIMPLE,
                        auto_bind=True,
                        raise_exceptions=True
                    )
                )
            except LDAPBindError:
                raise AuthenticationError("Invalid credentials")
            finally:
                if user_conn:
                    try:
                        user_conn.unbind()
                    except Exception as e:
                        logger.debug(f"Error unbinding user LDAP connection: {e}")

            # Extract user information
            user_info = {
                'username': str(user_entry.sAMAccountName or user_entry.uid or username),
                'email': str(user_entry.mail or ''),
                'full_name': str(user_entry.displayName or user_entry.cn or ''),
                'first_name': str(user_entry.givenName or ''),
                'last_name': str(user_entry.sn or ''),
                'title': str(user_entry.title or ''),
                'department': str(user_entry.department or ''),
                'phone': str(user_entry.telephoneNumber or user_entry.mobile or ''),
                'dn': user_dn,
                'groups': [],
                'attributes': {}
            }

            # Get user groups
            if hasattr(user_entry, 'memberOf'):
                groups = user_entry.memberOf
                if groups:
                    if isinstance(groups, str):
                        groups = [groups]
                    user_info['groups'] = [self._extract_group_name(g) for g in groups]

            # Store additional attributes
            for attr in self.user_attributes:
                if hasattr(user_entry, attr):
                    value = getattr(user_entry, attr)
                    if value:
                        user_info['attributes'][attr] = str(value)

            logger.info(f"Successfully authenticated user {username} via LDAP")
            return user_info

        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"LDAP authentication error: {e}")
            raise AuthenticationError(f"Authentication failed: {str(e)}")
        finally:
            await self._return_connection(conn)

    def _extract_group_name(self, group_dn: str) -> str:
        """Extract group name from DN"""
        # Extract CN from DN (e.g., "CN=Admins,OU=Groups,DC=example,DC=com" -> "Admins")
        parts = group_dn.split(',')
        for part in parts:
            if part.startswith('CN='):
                return part[3:]
        return group_dn

    async def get_user_groups(self, username: str) -> List[str]:
        """Get all groups for a user"""
        if not self.server:
            return []

        conn = await self._get_connection()
        if not conn:
            return []

        try:
            # Search for user
            search_filter = self.user_search_filter.format(username=username)

            await asyncio.get_event_loop().run_in_executor(
                None,
                conn.search,
                self.base_dn,
                search_filter,
                attributes=['memberOf']
            )

            if not conn.entries:
                return []

            user_entry = conn.entries[0]
            groups = []

            if hasattr(user_entry, 'memberOf'):
                member_of = user_entry.memberOf
                if member_of:
                    if isinstance(member_of, str):
                        member_of = [member_of]
                    groups = [self._extract_group_name(g) for g in member_of]

            return groups

        except Exception as e:
            logger.error(f"Failed to get user groups: {e}")
            return []
        finally:
            await self._return_connection(conn)

    async def search_users(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for users in LDAP"""
        if not self.server:
            return []

        conn = await self._get_connection()
        if not conn:
            return []

        try:
            # Build search filter
            search_filter = f"(&(|(cn=*{query}*)(mail=*{query}*)(sAMAccountName=*{query}*))(objectClass=person))"

            await asyncio.get_event_loop().run_in_executor(
                None,
                conn.search,
                self.base_dn,
                search_filter,
                attributes=self.user_attributes,
                size_limit=limit
            )

            users = []
            for entry in conn.entries:
                user_info = {
                    'username': str(entry.sAMAccountName or entry.uid or ''),
                    'email': str(entry.mail or ''),
                    'full_name': str(entry.displayName or entry.cn or ''),
                    'department': str(entry.department or ''),
                    'title': str(entry.title or '')
                }
                users.append(user_info)

            return users

        except Exception as e:
            logger.error(f"Failed to search users: {e}")
            return []
        finally:
            await self._return_connection(conn)

    async def validate_group_membership(self, username: str, required_groups: List[str]) -> bool:
        """Check if user is member of required groups"""
        user_groups = await self.get_user_groups(username)

        # Check if user has any of the required groups
        for required_group in required_groups:
            if required_group in user_groups:
                return True

        return False

    async def sync_user_to_database(
        self,
        ldap_info: Dict[str, Any],
        db: AsyncSession
    ) -> User:
        """Sync LDAP user information to database"""
        try:
            # Check if user exists
            stmt = select(User).where(User.username == ldap_info['username'])
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()

            if not user:
                # Create new user
                user = User(
                    username=ldap_info['username'],
                    email=ldap_info['email'],
                    full_name=ldap_info['full_name'],
                    is_active=True,
                    oauth_provider='ldap',
                    oauth_id=ldap_info['dn']
                )
                db.add(user)
            else:
                # Update existing user
                user.email = ldap_info['email']
                user.full_name = ldap_info['full_name']
                user.last_login_at = datetime.utcnow()

            # Map LDAP groups to roles
            await self._sync_user_roles(user, ldap_info['groups'], db)

            await db.commit()
            await db.refresh(user)

            return user

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to sync LDAP user to database: {e}")
            raise

    async def _sync_user_roles(self, user: User, ldap_groups: List[str], db: AsyncSession):
        """Sync user roles based on LDAP groups"""
        # Define LDAP group to role mappings
        group_role_mapping = {
            'CatNet-Admins': 'admin',
            'CatNet-Operators': 'operator',
            'CatNet-Viewers': 'viewer',
            'Network-Admins': 'network_admin',
            'Network-Engineers': 'network_engineer',
            'Domain Admins': 'admin'
        }

        # Clear existing roles
        user.roles = []

        # Add roles based on LDAP groups
        for ldap_group in ldap_groups:
            if ldap_group in group_role_mapping:
                role_name = group_role_mapping[ldap_group]

                # Get or create role
                stmt = select(Role).where(Role.name == role_name)
                result = await db.execute(stmt)
                role = result.scalar_one_or_none()

                if not role:
                    role = Role(
                        name=role_name,
                        description=f"Role mapped from LDAP group {ldap_group}",
                        permissions={
                            'deployment.view': True,
                            'deployment.create': role_name in ['admin', 'operator', 'network_admin'],
                            'deployment.approve': role_name in ['admin', 'network_admin'],
                            'device.view': True,
                            'device.connect': role_name in ['admin', 'operator', 'network_admin', 'network_engineer'],
                            'device.configure': role_name in ['admin', 'network_admin']
                        }
                    )
                    db.add(role)
                    await db.flush()

                if role not in user.roles:
                    user.roles.append(role)

    async def test_connection(self) -> bool:
        """Test LDAP connection"""
        if not self.server:
            return False

        conn = await self._get_connection()
        if not conn:
            return False

        try:
            # Try a simple search
            await asyncio.get_event_loop().run_in_executor(
                None,
                conn.search,
                self.base_dn,
                "(objectClass=*)",
                attributes=['dn'],
                size_limit=1
            )
            return True
        except Exception as e:
            logger.error(f"LDAP connection test failed: {e}")
            return False
        finally:
            await self._return_connection(conn)

    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user information by email"""
        if not self.server:
            return None

        conn = await self._get_connection()
        if not conn:
            return None

        try:
            search_filter = f"(&(mail={email})(objectClass=person))"

            await asyncio.get_event_loop().run_in_executor(
                None,
                conn.search,
                self.base_dn,
                search_filter,
                attributes=self.user_attributes
            )

            if not conn.entries:
                return None

            entry = conn.entries[0]
            return {
                'username': str(entry.sAMAccountName or entry.uid or ''),
                'email': str(entry.mail or ''),
                'full_name': str(entry.displayName or entry.cn or ''),
                'dn': entry.entry_dn
            }

        except Exception as e:
            logger.error(f"Failed to get user by email: {e}")
            return None
        finally:
            await self._return_connection(conn)

    async def close(self):
        """Close all LDAP connections"""
        while self._connection_pool:
            conn = self._connection_pool.pop()
            try:
                conn.unbind()
            except Exception as e:
                logger.debug(f"Error unbinding LDAP connection during close: {e}")
        logger.info("LDAP connections closed")


# Global LDAP authenticator instance
ldap_auth = LDAPAuthenticator()