.PHONY: test check lint validate

# Fast offline unit suite (UUID5 dedup + connector contract). No stack needed.
test:
	cd backend && python3 -m pytest -q

# Lint + type-check (best-effort; tools may not all be installed).
lint:
	cd backend && black --check app/ tests/ || true
	cd backend && pylint app/ || true

# Heavier: run every built-in connector with network/push mocked.
validate:
	python3 validate_connectors.py

# CI entry point: the checks that must pass on every push.
check: test
