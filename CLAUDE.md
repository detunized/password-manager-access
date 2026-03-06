# Build & Test

```bash
dotnet build
dotnet test
```

Run both after every task to verify.

# Code Style

- Use file-scoped namespaces in C#
- All new files should have `#nullable enable`
- Use `// Arrange`, `// Act`, `// Assert` comments in tests to group sections of code

# Git Conventions

- Use module prefixes in commit messages: `NordPass:`, `Bitwarden:`, `1Password:`, etc. Add ref #ISSUE when possible.
