run:
	go run ./cmd/cfasuite run all

setup:
	go run ./cmd/cfasuite setup --admin-password 'change-me-please' --force

assets:
	go run ./cmd/cfasuite assets build

.PHONY: run setup assets
