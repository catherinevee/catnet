# Contributing to CatNet

Thank you for considering contributing to CatNet! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Branch Naming Convention](#branch-naming-convention)
- [Documentation](#documentation)
- [Getting Help](#getting-help)

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Docker and Docker Compose
- Git
- PostgreSQL 14+ (or use Docker)
- Redis 7+ (or use Docker)
- HashiCorp Vault (or use Docker)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/catnet.git
   cd catnet
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/catherinevee/catnet.git
   ```

## Development Setup

### 1. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 3. Set Up Environment Variables

```bash
cp .env.example .env
# Edit .env with your local configuration
```

### 4. Start Development Services

```bash
docker-compose up -d postgres redis vault rabbitmq
```

### 5. Initialize Database

```bash
alembic upgrade head
```

### 6. Install Pre-commit Hooks

```bash
pre-commit install
```

### 7. Run the Application

```bash
uvicorn src.main:app --reload --port 8000
```

Visit http://localhost:8000/docs for the API documentation.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
- Check existing issues to avoid duplicates
- Collect information about the bug
- Try to reproduce it with the latest version

When filing a bug report, include:
- Clear, descriptive title
- Steps to reproduce
- Expected vs. actual behavior
- Screenshots (if applicable)
- Environment details (OS, Python version, etc.)
- Relevant logs

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:
- Check if it's already been suggested
- Provide clear use case
- Explain why it would be useful
- Consider implementation complexity

### Submitting Changes

1. Create a feature branch from `develop`
2. Make your changes
3. Write or update tests
4. Ensure all tests pass
5. Update documentation
6. Submit a pull request

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://peps.python.org/pep-0008/) with some modifications:

- **Line length:** 100 characters (not 79)
- **Quotes:** Double quotes for strings
- **Imports:** Sorted with `isort`
- **Formatting:** Automated with `black`

### Code Quality Tools

All code must pass:

```bash
# Formatting
black --check src/ tests/
isort --check-only src/ tests/

# Type checking
mypy src/ --strict

# Linting
pylint src/
flake8 src/

# Security
bandit -r src/
```

### Type Hints

- All functions must have type hints
- Use `typing` module for complex types
- Document return types, even if `None`

Example:
```python
from typing import List, Optional

def get_devices(
    filter_by: Optional[str] = None,
    limit: int = 100
) -> List[Device]:
    """Retrieve devices with optional filtering.

    Args:
        filter_by: Optional filter criterion
        limit: Maximum number of devices to return

    Returns:
        List of Device objects

    Raises:
        ValueError: If limit is negative
    """
    ...
```

### Docstrings

Use Google-style docstrings:

```python
def function_name(param1: str, param2: int) -> bool:
    """Brief description of function.

    More detailed description if needed.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ExceptionType: When this exception is raised
    """
    ...
```

### Error Handling

- Use custom exceptions from `src/core/exceptions.py`
- Always provide context in error messages
- Log errors appropriately
- Don't catch exceptions you can't handle

Example:
```python
from src.core.exceptions import DeviceConnectionError

try:
    device.connect()
except ConnectionError as e:
    logger.error(f"Failed to connect to device {device.id}: {e}")
    raise DeviceConnectionError(
        f"Cannot establish connection to {device.hostname}"
    ) from e
```

## Testing Requirements

### Writing Tests

- Write tests for all new code
- Aim for 80%+ code coverage
- Use descriptive test names
- Follow AAA pattern (Arrange, Act, Assert)

Test structure:
```python
def test_device_connection_success():
    """Test successful device connection."""
    # Arrange
    device = Device(hostname="router1", vendor="cisco_ios")

    # Act
    result = device.connect()

    # Assert
    assert result.is_connected
    assert result.connection_time < 5.0
```

### Test Categories

- **Unit Tests:** Test individual functions/classes
- **Integration Tests:** Test component interactions
- **E2E Tests:** Test complete workflows
- **Performance Tests:** Test system under load

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=src --cov-report=html

# Specific test file
pytest tests/unit/test_auth.py

# Specific test
pytest tests/unit/test_auth.py::test_login_success

# Watch mode (re-run on changes)
pytest-watch
```

### Test Fixtures

Use pytest fixtures for common setup:

```python
@pytest.fixture
def mock_device():
    """Provide a mock device for testing."""
    return Device(
        hostname="test-router",
        vendor="cisco_ios",
        username="admin"
    )

def test_device_backup(mock_device):
    """Test device backup functionality."""
    backup = mock_device.create_backup()
    assert backup.is_valid()
```

## Pull Request Process

### Before Submitting

1. **Update your fork:**
   ```bash
   git fetch upstream
   git rebase upstream/develop
   ```

2. **Run all checks:**
   ```bash
   black src/ tests/
   isort src/ tests/
   mypy src/
   pytest --cov=src --cov-fail-under=80
   ```

3. **Update documentation** if needed

4. **Add tests** for new functionality

### PR Guidelines

- **Title:** Clear, descriptive summary (max 72 chars)
- **Description:**
  - What changed and why
  - Link to related issues
  - Testing performed
  - Screenshots (if UI changes)
- **Size:** Keep PRs focused and reasonably sized
- **Tests:** All tests must pass
- **Coverage:** Don't decrease test coverage
- **Conflicts:** Resolve merge conflicts
- **Documentation:** Update relevant docs

### PR Template

```markdown
## Description
[Describe your changes]

## Related Issues
Fixes #123

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added and passing
- [ ] Coverage maintained/increased
```

### Review Process

1. Automated CI/CD checks run automatically
2. At least one maintainer review required
3. Address review comments
4. Maintainer approves and merges

## Commit Message Guidelines

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type

- **feat:** New feature
- **fix:** Bug fix
- **docs:** Documentation only
- **style:** Formatting changes (no code change)
- **refactor:** Code restructuring
- **perf:** Performance improvement
- **test:** Adding/updating tests
- **chore:** Maintenance tasks
- **ci:** CI/CD changes

### Examples

```bash
feat(auth): add LDAP authentication support

Implement LDAP authentication with connection pooling
and group mapping to RBAC roles.

Closes #456
```

```bash
fix(deployment): prevent race condition in rollback

Add mutex lock to prevent concurrent rollback operations
that could corrupt device state.

Fixes #789
```

```bash
docs(api): update authentication endpoint examples

Add examples for MFA flow and refresh token usage.
```

### Rules

- Use imperative mood ("add" not "added")
- First line max 72 characters
- Capitalize first letter
- No period at end of subject
- Separate subject from body with blank line
- Wrap body at 72 characters
- Explain what and why, not how

## Branch Naming Convention

Use descriptive branch names with prefixes:

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions/updates
- `chore/` - Maintenance tasks

Examples:
```bash
feature/ldap-authentication
fix/deployment-rollback-race-condition
docs/api-endpoint-examples
refactor/device-connection-pool
test/add-integration-tests
chore/update-dependencies
```

## Documentation

### Types of Documentation

1. **Code Comments**
   - Explain complex logic
   - Document edge cases
   - Add TODOs with issue numbers

2. **Docstrings**
   - All public functions/classes
   - Google-style format
   - Include examples for complex functions

3. **API Documentation**
   - Automatically generated from FastAPI
   - Keep endpoint descriptions updated
   - Provide request/response examples

4. **User Documentation**
   - README for getting started
   - Guides for common tasks
   - Troubleshooting section

5. **Developer Documentation**
   - Architecture decisions
   - Design patterns used
   - Integration guides

### Updating Documentation

- Update docs in the same PR as code changes
- Keep README.md current
- Update CHANGELOG.md for user-facing changes
- Add entries to docs/ for new features

## Getting Help

### Questions?

- Check existing [documentation](README.md)
- Search [existing issues](https://github.com/catherinevee/catnet/issues)
- Ask in [Discussions](https://github.com/catherinevee/catnet/discussions)
- Join our [Slack channel](#) (if available)

### Need Support?

- **Bugs:** [Open an issue](https://github.com/catherinevee/catnet/issues/new)
- **Features:** [Start a discussion](https://github.com/catherinevee/catnet/discussions/new)
- **Security:** See [SECURITY.md](SECURITY.md)

## Recognition

Contributors will be:
- Listed in [CONTRIBUTORS.md](CONTRIBUTORS.md)
- Credited in release notes
- Mentioned in project announcements

Thank you for contributing to CatNet! 🎉

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
