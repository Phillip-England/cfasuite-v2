run:
	go run ./cmd/cfasuite run all

setup:
	go run ./cmd/cfasuite setup --admin-password 'change-me-please' --force

assets:
	go run ./cmd/cfasuite assets build

E2E_BASE_URL ?= http://127.0.0.1:3000
E2E_API_PORT ?= 18080
E2E_CLIENT_PORT ?= 13000
E2E_ADMIN_USERNAME ?= admin
E2E_ADMIN_PASSWORD ?= change-me-please
E2E_DB_PATH ?= data.e2e.db
E2E_HEADLESS ?= false
E2E_SLOW_MO ?= 250
E2E_HOLD_MS ?= 500
E2E_BROWSER_CHANNEL ?= chromium
E2E_RUN_ID ?= $(shell date +%s)

.PHONY: run setup assets e2e-install e2e-deps e2e-browser-install e2e-create-location e2e

e2e-install:
	@if ! command -v uv >/dev/null 2>&1; then \
		echo "uv not found. install from https://docs.astral.sh/uv/getting-started/installation/"; \
		exit 1; \
	fi

e2e-deps: e2e-install
	uv sync --project e2e

e2e-browser-install: e2e-deps
	uv run --project e2e python -m playwright install chromium

e2e-create-location: e2e-browser-install
	E2E_BASE_URL="$(E2E_BASE_URL)" \
	E2E_ADMIN_USERNAME="$(E2E_ADMIN_USERNAME)" \
	E2E_ADMIN_PASSWORD="$(E2E_ADMIN_PASSWORD)" \
	E2E_HEADLESS="$(E2E_HEADLESS)" \
	E2E_SLOW_MO="$(E2E_SLOW_MO)" \
	E2E_HOLD_MS="$(E2E_HOLD_MS)" \
	E2E_BROWSER_CHANNEL="$(E2E_BROWSER_CHANNEL)" \
	E2E_RUN_ID="$(E2E_RUN_ID)" \
	uv run --project e2e python -m pytest e2e/tests_py/test_01_create_location.py

e2e: e2e-browser-install
	set -e; \
	rm -f "$(E2E_DB_PATH)"; \
	API_ADDR=":$(E2E_API_PORT)" \
	CLIENT_ADDR=":$(E2E_CLIENT_PORT)" \
	API_BASE_URL="http://127.0.0.1:$(E2E_API_PORT)" \
	AUTH_DB_PATH="$(E2E_DB_PATH)" \
	ADMIN_USERNAME="$(E2E_ADMIN_USERNAME)" \
	ADMIN_PASSWORD="$(E2E_ADMIN_PASSWORD)" \
	go run ./cmd/cfasuite run all >/tmp/cfasuite-e2e.log 2>&1 & \
	APP_PID=$$!; \
	trap 'kill $$APP_PID >/dev/null 2>&1 || true' EXIT; \
	until curl -fsS "http://127.0.0.1:$(E2E_CLIENT_PORT)/" >/dev/null 2>&1; do \
		if ! kill -0 $$APP_PID >/dev/null 2>&1; then \
			echo "cfasuite failed to start; /tmp/cfasuite-e2e.log:"; \
			cat /tmp/cfasuite-e2e.log; \
			exit 1; \
		fi; \
		sleep 1; \
	done; \
	E2E_BASE_URL="http://127.0.0.1:$(E2E_CLIENT_PORT)" \
	E2E_ADMIN_USERNAME="$(E2E_ADMIN_USERNAME)" \
	E2E_ADMIN_PASSWORD="$(E2E_ADMIN_PASSWORD)" \
	E2E_HEADLESS="$(E2E_HEADLESS)" \
	E2E_SLOW_MO="$(E2E_SLOW_MO)" \
	E2E_HOLD_MS="$(E2E_HOLD_MS)" \
	E2E_BROWSER_CHANNEL="$(E2E_BROWSER_CHANNEL)" \
	E2E_RUN_ID="$(E2E_RUN_ID)" \
	sh -c ' \
		echo "Running Python e2e in browser mode: E2E_HEADLESS=$(E2E_HEADLESS), E2E_SLOW_MO=$(E2E_SLOW_MO), E2E_HOLD_MS=$(E2E_HOLD_MS), E2E_BROWSER_CHANNEL=$(E2E_BROWSER_CHANNEL), E2E_RUN_ID=$(E2E_RUN_ID)"; \
		echo "==> [1/4] create location"; \
		uv run --project e2e python -m pytest e2e/tests_py/test_01_create_location.py; \
		echo "==> [2/4] create employees"; \
		uv run --project e2e python -m pytest e2e/tests_py/test_02_create_employees.py; \
		echo "==> [3/4] submit paperwork"; \
		uv run --project e2e python -m pytest e2e/tests_py/test_03_submit_paperwork.py; \
		echo "==> [4/4] hire candidates"; \
		uv run --project e2e python -m pytest e2e/tests_py/test_04_hire_candidates.py; \
		echo "E2E complete. Data is in $(E2E_DB_PATH) for manual verification."; \
	'
