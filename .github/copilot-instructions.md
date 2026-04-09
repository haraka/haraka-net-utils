# Haraka Monorepo – Copilot Instructions

## Repository Overview

This is the **Haraka** monorepo — a highly scalable Node.js SMTP email server ecosystem. Each subdirectory is an independent npm package with its own `package.json`, tests, and version history. There is no root `package.json`; packages are not linked via npm workspaces.

**Main packages:**
- `Haraka/` – Core SMTP server
- `plugin/` – 40+ optional plugins (bounce, dkim, spf, rspamd, relay, karma, etc.)
- `address-rfc2821/`, `address-rfc2822/` – RFC-compliant email address parsers
- `haraka-config/` – Config file loader with hot-reload support
- `results/`, `notes/` – Per-connection result and note tracking
- `net-utils/`, `utils/`, `constants/`, `dsn/`, `tld/` – Shared utility libraries
- `eslint/` – Shared ESLint config (`@haraka/eslint-config`)
- `test-fixtures/` – Shared test fixtures (`haraka-test-fixtures`)

## Commands

All commands are run from within the relevant package directory (e.g., `cd Haraka`).

```bash
# Test
npm test                              # Run full test suite
node --test test/path/to/file.js      # Run a single test file (node:test packages)
npx mocha test/path/to/file.js        # Run a single test file (mocha packages)

# Test coverage
npm run test:coverage                 # Run tests with coverage

# In Haraka/ specifically:
./run_tests                           # Same as npm test
./run_tests test/plugins/bounce.js    # Single test file

# Lint & format
npm run lint                          # ESLint check
npm run lint:fix                      # Auto-fix lint issues
npm run prettier                      # Check formatting
npm run prettier:fix                  # Auto-format
npm run format                        # prettier:fix + lint:fix (run before committing)

# Dependency version management
npm run versions                      # Check for version drift
npm run versions:fix                  # Update versions
```

## Architecture

### Plugin System

Plugins are the primary extension mechanism. Patterns and instructions for plugins are documented in ./Haraka/docs/Plugins.md.

### Config Loading

Config files are loaded via `config.get()`, which supports hot-reload:

```javascript
exports.load_my_ini = function () {
  this.cfg = this.config.get('plugin-name.ini', {
    booleans: ['+feature.enabled', '-feature.other'],
  }, () => { this.load_my_ini() })  // callback re-runs on file change
}
```

### Inter-Package Dependencies

Utility packages (`haraka-utils`, `haraka-net-utils`, `haraka-constants`, etc.) are standalone and imported via `require()` by both `Haraka/` and plugins. Plugins sometimes depend on each other (e.g., `haraka-plugin-bounce` depends on `haraka-plugin-spf`).

## Conventions

### Module Format

All code uses **CommonJS** (`require` / `module.exports` / `exports`).

### Code Style (enforced by ESLint + Prettier)

- use prettier
- `true`/`false` instead of `1`/`0`
- Prefer template literals over string concatenation
- Remove commented-out code; it lives in git history
- When updating files, add `node:` prefixes to any Node.js built-in `require()` calls that lack them (e.g. `require('fs')` → `require('node:fs')`)

### Test Structure

The codebase is **migrating from Mocha to `node:test`**. New tests should use `node:test`. Many existing tests still use Mocha — updating them to be more compatible is welcome.

**New style (`node:test`):**
```javascript
const assert = require('node:assert/strict')
const { beforeEach, describe, it } = require('node:test')
const subject = require('../index')

describe('feature', () => {
  beforeEach(() => { /* setup */ })

  it('does X', async () => {
    const result = await subject.doSomething()
    assert.deepEqual(result, expected)
  })
})
```

**Old style (Mocha — still present in many packages):**
```javascript
const assert = require('assert')
const subject = require('../index')

describe('feature', function () {
  it('does X', function (done) {
    assert.equal(subject.doSomething(), expected)
    done()
  })
})
```

The key difference: `node:test` requires explicitly importing `describe`/`it`/`beforeEach` etc. from `'node:test'`. Use `node:assert` and `node:` prefixes for builtins. Avoid `done` callbacks — use `async`/`await` instead.

Common test dependencies: `haraka-test-fixtures`, `sinon`, `mock-require`.

### Plugin Package Layout

```
plugin/my-plugin/
├── index.js          # Plugin code (exports.register + hook handlers)
├── package.json      # { "name": "haraka-plugin-my-plugin", "main": "index.js" }
├── config/           # Default config files (.ini, .yaml, .json)
├── test/
│   └── index.js
└── README.md
```

### Utility Package Layout

```
my-util/
├── index.js          # Functional exports or class export
├── package.json      # { "name": "haraka-my-util" }
└── test/
    └── index.js
```
