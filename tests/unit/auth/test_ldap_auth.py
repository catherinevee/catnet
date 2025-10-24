"""
Comprehensive unit tests for LDAP/Active Directory authentication
Tests LDAP connection, user authentication, group management, and database sync
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock, PropertyMock
from ldap3 import Server, Connection, SIMPLE
from ldap3.core.exceptions import LDAPException, LDAPBindError
import asyncio

from src.auth.ldap_auth import LDAPAuthenticator
from src.core.exceptions import AuthenticationError, AuthorizationError
from src.db.models import User, Role


@pytest.fixture
def mock_settings():
    """Mock settings for LDAP configuration."""
    with patch('src.auth.ldap_auth.settings') as mock:
        mock.ldap_server = "ldap://ldap.example.com:389"
        mock.ldap_base_dn = "dc=example,dc=com"
        mock.ldap_bind_dn = "cn=admin,dc=example,dc=com"
        mock.ldap_bind_password = Mock()
        mock.ldap_bind_password.get_secret_value.return_value = "admin_password"
        yield mock


@pytest.fixture
def ldap_authenticator(mock_settings):
    """Provide LDAP authenticator instance."""
    with patch('src.auth.ldap_auth.Server'):
        authenticator = LDAPAuthenticator()
        return authenticator


@pytest.fixture
def mock_ldap_server():
    """Mock LDAP server."""
    server = Mock(spec=Server)
    return server


@pytest.fixture
def mock_ldap_connection():
    """Mock LDAP connection."""
    conn = Mock(spec=Connection)
    conn.bound = True
    conn.entries = []
    conn.search = Mock(return_value=True)
    conn.unbind = Mock()
    return conn


@pytest.fixture
def mock_user_entry():
    """Mock LDAP user entry."""
    entry = Mock()
    entry.entry_dn = "cn=jdoe,ou=users,dc=example,dc=com"
    entry.sAMAccountName = "jdoe"
    entry.uid = "jdoe"
    entry.mail = "jdoe@example.com"
    entry.displayName = "John Doe"
    entry.cn = "John Doe"
    entry.givenName = "John"
    entry.sn = "Doe"
    entry.title = "Network Engineer"
    entry.department = "IT"
    entry.telephoneNumber = "+1-555-0123"
    entry.mobile = "+1-555-0456"
    entry.userPrincipalName = "jdoe@example.com"
    entry.memberOf = [
        "CN=Network-Engineers,OU=Groups,DC=example,DC=com",
        "CN=CatNet-Operators,OU=Groups,DC=example,DC=com"
    ]
    return entry


@pytest.fixture
def mock_db_session():
    """Mock database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    session.add = Mock()
    session.flush = AsyncMock()
    return session


class TestLDAPInitialization:
    """Test LDAP authenticator initialization."""

    def test_init_with_ldap_server(self, mock_settings):
        """Test initialization with LDAP server configured."""
        with patch('src.auth.ldap_auth.Server') as mock_server:
            authenticator = LDAPAuthenticator()

            assert authenticator.base_dn == "dc=example,dc=com"
            assert authenticator.bind_dn == "cn=admin,dc=example,dc=com"
            assert authenticator.bind_password == "admin_password"
            assert mock_server.called

    def test_init_with_ldaps_server(self, mock_settings):
        """Test initialization with LDAPS (SSL) server."""
        mock_settings.ldap_server = "ldaps://ldap.example.com:636"

        with patch('src.auth.ldap_auth.Server') as mock_server:
            authenticator = LDAPAuthenticator()

            # Verify SSL is used
            call_args = mock_server.call_args
            assert call_args[1]['use_ssl'] is True
            assert call_args[1]['port'] == 636

    def test_init_with_custom_port(self, mock_settings):
        """Test initialization with custom LDAP port."""
        mock_settings.ldap_server = "ldap://ldap.example.com:1389"

        with patch('src.auth.ldap_auth.Server') as mock_server:
            authenticator = LDAPAuthenticator()

            call_args = mock_server.call_args
            assert call_args[1]['port'] == 1389

    def test_init_without_ldap_server(self, mock_settings):
        """Test initialization without LDAP server configured."""
        mock_settings.ldap_server = None

        with patch('src.auth.ldap_auth.Server') as mock_server:
            authenticator = LDAPAuthenticator()

            assert authenticator.server is None
            assert not mock_server.called

    def test_init_connection_pool(self, ldap_authenticator):
        """Test connection pool is initialized."""
        assert ldap_authenticator._connection_pool == []
        assert ldap_authenticator._pool_size == 5


class TestLDAPConnection:
    """Test LDAP connection management."""

    @pytest.mark.asyncio
    async def test_get_connection_creates_new(self, ldap_authenticator):
        """Test getting connection creates new one if pool is empty."""
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True

        with patch.object(ldap_authenticator, '_create_connection', return_value=mock_conn):
            conn = await ldap_authenticator._get_connection()

            assert conn == mock_conn

    @pytest.mark.asyncio
    async def test_get_connection_from_pool(self, ldap_authenticator):
        """Test getting connection from pool."""
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        ldap_authenticator._connection_pool.append(mock_conn)

        conn = await ldap_authenticator._get_connection()

        assert conn == mock_conn
        assert len(ldap_authenticator._connection_pool) == 0

    @pytest.mark.asyncio
    async def test_get_connection_skips_unbound(self, ldap_authenticator):
        """Test getting connection skips unbound connections."""
        unbound_conn = Mock(spec=Connection)
        unbound_conn.bound = False
        unbound_conn.unbind = Mock()

        bound_conn = Mock(spec=Connection)
        bound_conn.bound = True

        ldap_authenticator._connection_pool.extend([unbound_conn, bound_conn])

        conn = await ldap_authenticator._get_connection()

        assert conn == bound_conn
        assert unbound_conn.unbind.called

    @pytest.mark.asyncio
    async def test_return_connection_to_pool(self, ldap_authenticator):
        """Test returning connection to pool."""
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True

        await ldap_authenticator._return_connection(mock_conn)

        assert len(ldap_authenticator._connection_pool) == 1
        assert ldap_authenticator._connection_pool[0] == mock_conn

    @pytest.mark.asyncio
    async def test_return_connection_pool_full(self, ldap_authenticator):
        """Test connection is closed when pool is full."""
        ldap_authenticator._connection_pool = [Mock()] * 5  # Fill pool

        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.unbind = Mock()

        await ldap_authenticator._return_connection(mock_conn)

        assert len(ldap_authenticator._connection_pool) == 5
        assert mock_conn.unbind.called

    @pytest.mark.asyncio
    async def test_get_connection_without_server(self, ldap_authenticator):
        """Test getting connection fails without server."""
        ldap_authenticator.server = None

        conn = await ldap_authenticator._get_connection()

        assert conn is None


class TestLDAPAuthentication:
    """Test LDAP user authentication."""

    @pytest.mark.asyncio
    async def test_authenticate_success(self, ldap_authenticator, mock_ldap_connection, mock_user_entry):
        """Test successful LDAP authentication."""
        mock_ldap_connection.entries = [mock_user_entry]

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                with patch('src.auth.ldap_auth.Connection') as mock_conn_class:
                    # Mock user bind success
                    mock_user_conn = Mock()
                    mock_user_conn.unbind = Mock()
                    mock_conn_class.return_value = mock_user_conn

                    user_info = await ldap_authenticator.authenticate("jdoe", "password123")

                    assert user_info['username'] == "jdoe"
                    assert user_info['email'] == "jdoe@example.com"
                    assert user_info['full_name'] == "John Doe"
                    assert user_info['first_name'] == "John"
                    assert user_info['last_name'] == "Doe"
                    assert "Network-Engineers" in user_info['groups']
                    assert "CatNet-Operators" in user_info['groups']

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, ldap_authenticator, mock_ldap_connection):
        """Test authentication fails when user not found."""
        mock_ldap_connection.entries = []

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                with pytest.raises(AuthenticationError) as exc_info:
                    await ldap_authenticator.authenticate("nonexistent", "password")

                assert "not found in LDAP" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_authenticate_invalid_credentials(self, ldap_authenticator, mock_ldap_connection, mock_user_entry):
        """Test authentication fails with wrong password."""
        mock_ldap_connection.entries = [mock_user_entry]

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                with patch('src.auth.ldap_auth.Connection', side_effect=LDAPBindError):
                    with pytest.raises(AuthenticationError) as exc_info:
                        await ldap_authenticator.authenticate("jdoe", "wrong_password")

                    assert "Invalid credentials" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_authenticate_no_server(self, ldap_authenticator):
        """Test authentication fails without LDAP server."""
        ldap_authenticator.server = None

        with pytest.raises(AuthenticationError) as exc_info:
            await ldap_authenticator.authenticate("jdoe", "password")

        assert "not available" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_authenticate_connection_failed(self, ldap_authenticator):
        """Test authentication fails when connection fails."""
        with patch.object(ldap_authenticator, '_get_connection', return_value=None):
            with pytest.raises(AuthenticationError) as exc_info:
                await ldap_authenticator.authenticate("jdoe", "password")

            assert "Failed to connect" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_authenticate_with_email(self, ldap_authenticator, mock_ldap_connection, mock_user_entry):
        """Test authentication with email address."""
        mock_ldap_connection.entries = [mock_user_entry]

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                with patch('src.auth.ldap_auth.Connection'):
                    user_info = await ldap_authenticator.authenticate("jdoe@example.com", "password")

                    assert user_info['username'] == "jdoe"

    @pytest.mark.asyncio
    async def test_authenticate_user_without_groups(self, ldap_authenticator, mock_ldap_connection):
        """Test authentication for user without group memberships."""
        entry = Mock()
        entry.entry_dn = "cn=user,dc=example,dc=com"
        entry.sAMAccountName = "user"
        entry.mail = "user@example.com"
        entry.displayName = "Test User"
        # No memberOf attribute

        mock_ldap_connection.entries = [entry]

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                with patch('src.auth.ldap_auth.Connection'):
                    user_info = await ldap_authenticator.authenticate("user", "password")

                    assert user_info['groups'] == []


class TestGroupExtraction:
    """Test LDAP group extraction and management."""

    def test_extract_group_name_from_dn(self, ldap_authenticator):
        """Test extracting group name from DN."""
        dn = "CN=Network-Admins,OU=Groups,DC=example,DC=com"

        group_name = ldap_authenticator._extract_group_name(dn)

        assert group_name == "Network-Admins"

    def test_extract_group_name_complex_dn(self, ldap_authenticator):
        """Test extracting from complex DN."""
        dn = "CN=Domain Admins,OU=Security Groups,OU=Groups,DC=corp,DC=example,DC=com"

        group_name = ldap_authenticator._extract_group_name(dn)

        assert group_name == "Domain Admins"

    def test_extract_group_name_no_cn(self, ldap_authenticator):
        """Test extraction when CN is not present."""
        dn = "OU=Groups,DC=example,DC=com"

        group_name = ldap_authenticator._extract_group_name(dn)

        assert group_name == dn

    @pytest.mark.asyncio
    async def test_get_user_groups(self, ldap_authenticator, mock_ldap_connection):
        """Test getting user groups."""
        entry = Mock()
        entry.memberOf = [
            "CN=Admins,DC=example,DC=com",
            "CN=Users,DC=example,DC=com"
        ]
        mock_ldap_connection.entries = [entry]

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                groups = await ldap_authenticator.get_user_groups("testuser")

                assert "Admins" in groups
                assert "Users" in groups

    @pytest.mark.asyncio
    async def test_get_user_groups_user_not_found(self, ldap_authenticator, mock_ldap_connection):
        """Test getting groups for non-existent user."""
        mock_ldap_connection.entries = []

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                groups = await ldap_authenticator.get_user_groups("nonexistent")

                assert groups == []

    @pytest.mark.asyncio
    async def test_validate_group_membership_success(self, ldap_authenticator):
        """Test validating user group membership."""
        with patch.object(ldap_authenticator, 'get_user_groups', return_value=["Admins", "Users"]):
            is_member = await ldap_authenticator.validate_group_membership("user", ["Admins"])

            assert is_member is True

    @pytest.mark.asyncio
    async def test_validate_group_membership_failure(self, ldap_authenticator):
        """Test validation fails when user not in required groups."""
        with patch.object(ldap_authenticator, 'get_user_groups', return_value=["Users"]):
            is_member = await ldap_authenticator.validate_group_membership("user", ["Admins"])

            assert is_member is False

    @pytest.mark.asyncio
    async def test_validate_group_membership_multiple_groups(self, ldap_authenticator):
        """Test validation with multiple required groups (OR logic)."""
        with patch.object(ldap_authenticator, 'get_user_groups', return_value=["Users"]):
            is_member = await ldap_authenticator.validate_group_membership("user", ["Admins", "Users"])

            assert is_member is True


class TestUserSearch:
    """Test LDAP user search functionality."""

    @pytest.mark.asyncio
    async def test_search_users(self, ldap_authenticator, mock_ldap_connection):
        """Test searching for users."""
        entry1 = Mock()
        entry1.sAMAccountName = "jdoe"
        entry1.mail = "jdoe@example.com"
        entry1.displayName = "John Doe"
        entry1.cn = "John Doe"
        entry1.department = "IT"
        entry1.title = "Engineer"

        entry2 = Mock()
        entry2.sAMAccountName = "jsmith"
        entry2.mail = "jsmith@example.com"
        entry2.displayName = "Jane Smith"
        entry2.cn = "Jane Smith"
        entry2.department = "HR"
        entry2.title = "Manager"

        mock_ldap_connection.entries = [entry1, entry2]

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                users = await ldap_authenticator.search_users("john")

                assert len(users) == 2
                assert users[0]['username'] == "jdoe"
                assert users[1]['username'] == "jsmith"

    @pytest.mark.asyncio
    async def test_search_users_no_results(self, ldap_authenticator, mock_ldap_connection):
        """Test search with no results."""
        mock_ldap_connection.entries = []

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                users = await ldap_authenticator.search_users("nonexistent")

                assert users == []

    @pytest.mark.asyncio
    async def test_search_users_without_server(self, ldap_authenticator):
        """Test search fails gracefully without server."""
        ldap_authenticator.server = None

        users = await ldap_authenticator.search_users("john")

        assert users == []

    @pytest.mark.asyncio
    async def test_get_user_by_email(self, ldap_authenticator, mock_ldap_connection):
        """Test getting user by email address."""
        entry = Mock()
        entry.sAMAccountName = "jdoe"
        entry.mail = "jdoe@example.com"
        entry.displayName = "John Doe"
        entry.cn = "John Doe"
        entry.entry_dn = "cn=jdoe,dc=example,dc=com"

        mock_ldap_connection.entries = [entry]

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                user = await ldap_authenticator.get_user_by_email("jdoe@example.com")

                assert user['username'] == "jdoe"
                assert user['email'] == "jdoe@example.com"

    @pytest.mark.asyncio
    async def test_get_user_by_email_not_found(self, ldap_authenticator, mock_ldap_connection):
        """Test getting user by non-existent email."""
        mock_ldap_connection.entries = []

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                user = await ldap_authenticator.get_user_by_email("nonexistent@example.com")

                assert user is None


class TestDatabaseSync:
    """Test syncing LDAP users to database."""

    @pytest.mark.asyncio
    async def test_sync_user_to_database_new_user(self, ldap_authenticator, mock_db_session):
        """Test syncing new LDAP user to database."""
        ldap_info = {
            'username': 'jdoe',
            'email': 'jdoe@example.com',
            'full_name': 'John Doe',
            'dn': 'cn=jdoe,dc=example,dc=com',
            'groups': ['CatNet-Admins']
        }

        # Mock user not exists
        result = Mock()
        result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = result

        with patch.object(ldap_authenticator, '_sync_user_roles', new_callable=AsyncMock):
            user = await ldap_authenticator.sync_user_to_database(ldap_info, mock_db_session)

            assert mock_db_session.add.called
            assert mock_db_session.commit.called

    @pytest.mark.asyncio
    async def test_sync_user_to_database_existing_user(self, ldap_authenticator, mock_db_session):
        """Test syncing existing LDAP user."""
        ldap_info = {
            'username': 'jdoe',
            'email': 'jdoe@example.com',
            'full_name': 'John Doe',
            'dn': 'cn=jdoe,dc=example,dc=com',
            'groups': ['CatNet-Operators']
        }

        # Mock existing user
        existing_user = Mock(spec=User)
        existing_user.username = 'jdoe'
        result = Mock()
        result.scalar_one_or_none.return_value = existing_user
        mock_db_session.execute.return_value = result

        with patch.object(ldap_authenticator, '_sync_user_roles', new_callable=AsyncMock):
            user = await ldap_authenticator.sync_user_to_database(ldap_info, mock_db_session)

            assert existing_user.email == 'jdoe@example.com'
            assert mock_db_session.commit.called

    @pytest.mark.asyncio
    async def test_sync_user_roles(self, ldap_authenticator, mock_db_session):
        """Test syncing user roles from LDAP groups."""
        user = Mock(spec=User)
        user.roles = []

        ldap_groups = ['CatNet-Admins', 'Network-Engineers']

        # Mock role lookup
        admin_role = Mock(spec=Role)
        admin_role.name = 'admin'
        engineer_role = Mock(spec=Role)
        engineer_role.name = 'network_engineer'

        results = [
            Mock(scalar_one_or_none=Mock(return_value=admin_role)),
            Mock(scalar_one_or_none=Mock(return_value=engineer_role))
        ]
        mock_db_session.execute.side_effect = results

        await ldap_authenticator._sync_user_roles(user, ldap_groups, mock_db_session)

        assert len(user.roles) == 2

    @pytest.mark.asyncio
    async def test_sync_user_roles_creates_missing_roles(self, ldap_authenticator, mock_db_session):
        """Test role creation when LDAP group doesn't have matching role."""
        user = Mock(spec=User)
        user.roles = []

        ldap_groups = ['CatNet-Admins']

        # Mock role doesn't exist
        result = Mock()
        result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = result

        await ldap_authenticator._sync_user_roles(user, ldap_groups, mock_db_session)

        assert mock_db_session.add.called
        assert mock_db_session.flush.called

    @pytest.mark.asyncio
    async def test_sync_user_database_rollback_on_error(self, ldap_authenticator, mock_db_session):
        """Test database rollback on sync error."""
        ldap_info = {
            'username': 'jdoe',
            'email': 'jdoe@example.com',
            'full_name': 'John Doe',
            'dn': 'cn=jdoe,dc=example,dc=com',
            'groups': []
        }

        # Simulate database error
        mock_db_session.execute.side_effect = Exception("Database error")

        with pytest.raises(Exception):
            await ldap_authenticator.sync_user_to_database(ldap_info, mock_db_session)

        assert mock_db_session.rollback.called


class TestConnectionTesting:
    """Test LDAP connection testing."""

    @pytest.mark.asyncio
    async def test_test_connection_success(self, ldap_authenticator, mock_ldap_connection):
        """Test successful connection test."""
        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                result = await ldap_authenticator.test_connection()

                assert result is True

    @pytest.mark.asyncio
    async def test_test_connection_no_server(self, ldap_authenticator):
        """Test connection test without server."""
        ldap_authenticator.server = None

        result = await ldap_authenticator.test_connection()

        assert result is False

    @pytest.mark.asyncio
    async def test_test_connection_failed(self, ldap_authenticator, mock_ldap_connection):
        """Test connection test failure."""
        mock_ldap_connection.search = Mock(side_effect=LDAPException("Connection failed"))

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                result = await ldap_authenticator.test_connection()

                assert result is False


class TestConnectionCleanup:
    """Test LDAP connection cleanup."""

    @pytest.mark.asyncio
    async def test_close_connections(self, ldap_authenticator):
        """Test closing all connections in pool."""
        conn1 = Mock()
        conn1.unbind = Mock()
        conn2 = Mock()
        conn2.unbind = Mock()

        ldap_authenticator._connection_pool = [conn1, conn2]

        await ldap_authenticator.close()

        assert len(ldap_authenticator._connection_pool) == 0
        assert conn1.unbind.called
        assert conn2.unbind.called

    @pytest.mark.asyncio
    async def test_close_connections_handles_errors(self, ldap_authenticator):
        """Test closing connections handles errors gracefully."""
        conn = Mock()
        conn.unbind = Mock(side_effect=Exception("Unbind error"))

        ldap_authenticator._connection_pool = [conn]

        # Should not raise exception
        await ldap_authenticator.close()

        assert len(ldap_authenticator._connection_pool) == 0


class TestLDAPEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_authenticate_with_special_characters(self, ldap_authenticator, mock_ldap_connection, mock_user_entry):
        """Test authentication with special characters in username."""
        mock_user_entry.sAMAccountName = "user.name@domain"
        mock_ldap_connection.entries = [mock_user_entry]

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                with patch('src.auth.ldap_auth.Connection'):
                    user_info = await ldap_authenticator.authenticate("user.name@domain", "password")

                    assert user_info['username'] == "user.name@domain"

    @pytest.mark.asyncio
    async def test_authenticate_single_group(self, ldap_authenticator, mock_ldap_connection):
        """Test authentication when user has single group (string instead of list)."""
        entry = Mock()
        entry.entry_dn = "cn=user,dc=example,dc=com"
        entry.sAMAccountName = "user"
        entry.mail = "user@example.com"
        entry.displayName = "User"
        entry.memberOf = "CN=Users,DC=example,DC=com"  # Single string, not list

        mock_ldap_connection.entries = [entry]

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                with patch('src.auth.ldap_auth.Connection'):
                    user_info = await ldap_authenticator.authenticate("user", "password")

                    assert "Users" in user_info['groups']

    @pytest.mark.asyncio
    async def test_authenticate_missing_optional_attributes(self, ldap_authenticator, mock_ldap_connection):
        """Test authentication with missing optional attributes."""
        entry = Mock()
        entry.entry_dn = "cn=user,dc=example,dc=com"
        entry.sAMAccountName = "user"
        entry.mail = "user@example.com"
        # No displayName, givenName, sn, etc.

        # Simulate missing attributes by raising AttributeError
        type(entry).displayName = PropertyMock(side_effect=AttributeError)
        type(entry).cn = PropertyMock(return_value="user")
        type(entry).givenName = PropertyMock(side_effect=AttributeError)
        type(entry).sn = PropertyMock(side_effect=AttributeError)
        type(entry).title = PropertyMock(side_effect=AttributeError)
        type(entry).department = PropertyMock(side_effect=AttributeError)
        type(entry).telephoneNumber = PropertyMock(side_effect=AttributeError)
        type(entry).mobile = PropertyMock(side_effect=AttributeError)

        mock_ldap_connection.entries = [entry]

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                with patch('src.auth.ldap_auth.Connection'):
                    user_info = await ldap_authenticator.authenticate("user", "password")

                    assert user_info['username'] == "user"
                    assert user_info['full_name'] == "user"  # Falls back to cn

    @pytest.mark.asyncio
    async def test_search_users_with_limit(self, ldap_authenticator, mock_ldap_connection):
        """Test user search respects limit parameter."""
        entries = [Mock() for _ in range(100)]
        for i, entry in enumerate(entries):
            entry.sAMAccountName = f"user{i}"
            entry.mail = f"user{i}@example.com"
            entry.displayName = f"User {i}"
            entry.cn = f"User {i}"
            entry.department = "IT"
            entry.title = "Employee"

        mock_ldap_connection.entries = entries[:50]  # Server returns limited results

        with patch.object(ldap_authenticator, '_get_connection', return_value=mock_ldap_connection):
            with patch.object(ldap_authenticator, '_return_connection', new_callable=AsyncMock):
                users = await ldap_authenticator.search_users("user", limit=50)

                assert len(users) == 50
