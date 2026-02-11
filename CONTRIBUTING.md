# Contributing

Thank you for your interest in contributing to go-appsec/toolbox!

## Getting Started

**Setup:**
```bash
# Fork the repository, then clone your fork
git clone https://github.com/YOUR_USERNAME/toolbox
cd toolbox

# Install dependencies
go mod download

# Verify your setup
make test-all
```

## Development Workflow

**Available Commands:**
```bash
make test        # Run fast tests
make test-all    # Run tests, including network + integration, with race detection and coverage
make test-cover  # Generate HTML coverage report
make bench       # Run benchmarks
make lint        # Run linting and static analysis
```

## Pull Requests

1. Create a feature branch on your personal fork
2. Make your changes following existing code patterns. Ensure testing is also added to cover the feature or bug behavior.
3. Run `make test-all && make lint` to verify everything passes
4. Commit with clear, descriptive messages
5. Push to your fork and open a pull request
6. Describe your changes and link any related issues

## Need Help?

If you have questions or need guidance, please [open an issue](https://github.com/go-appsec/toolbox/issues/new?template=question.md) and we'll be happy to help!
