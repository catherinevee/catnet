# Contributing to CatNet

Thank you for considering contributing to CatNet! We welcome contributions from the community and are excited to work with you.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please report unacceptable behavior to security@catnet.io.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- System information (OS, Python version, etc.)
- Relevant logs and error messages

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When suggesting an enhancement:

- Use a clear and descriptive title
- Provide a detailed description of the proposed feature
- Include examples of how the feature would be used
- Explain why this enhancement would be useful

### Pull Requests

1. Fork the repository and create your branch from `main`
2. If you've added code, add tests that cover your changes
3. Ensure the test suite passes: `make test`
4. Make sure your code follows our style guidelines: `make lint`
5. Format your code: `make format`
6. Write a clear commit message following conventional commits

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/catnet.git
cd catnet

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
make dev-install

# Run tests
make test

# Start development environment
make dev
```

## Style Guidelines

### Python Style

- Follow PEP 8
- Use Black for formatting (line length: 88)
- Use type hints for all function signatures
- Write docstrings for all public functions and classes

### Commit Messages

We use conventional commits format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes

### Security Guidelines

- Never commit credentials or secrets
- Use HashiCorp Vault for all secret management
- Follow security best practices in SECURITY_ARCHITECTURE.md
- Run security tests: `make test-security`

## Testing

All code must have appropriate test coverage:

- Unit tests for individual functions/classes
- Integration tests for API endpoints
- End-to-end tests for critical workflows
- Security tests for authentication/authorization

```bash
# Run all tests
make test

# Run specific test category
make test-unit
make test-integration
make test-security
```

## Documentation

- Update documentation for any API changes
- Include docstrings for new functions/classes
- Update README if adding new features
- Add examples for new functionality

## Review Process

1. All submissions require review before merging
2. Reviewers will check:
   - Code quality and style
   - Test coverage
   - Security implications
   - Documentation updates
3. Address all review comments
4. Squash commits before final merge

## Release Process

1. Ensure all tests pass on main branch
2. Update version in `pyproject.toml`
3. Update CHANGELOG.md
4. Create a tagged release
5. Deploy to staging for verification
6. Deploy to production

## Questions?

Feel free to open an issue for any questions or join our community discussions.

Thank you for contributing to CatNet!