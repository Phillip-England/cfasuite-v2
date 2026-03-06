
run:
	go run ./cmd/cfasuite run all

setup:
	go run ./cmd/cfasuite setup --admin-password 'change-me-please' --force

assets:
	go run ./cmd/cfasuite assets build

test:
	go run ./cmd/cfasuite reset
	bdr run ./e2e/test.bdr;

reset:
	go run ./cmd/cfasuite reset
	touch data.db messages.db

.PHONY: run setup assets test reset
