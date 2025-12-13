.PHONY: produce consume run

produce:
	@go run cmd/producer/main.go

consume:
	@go run cmd/aggregator/main.go

run:
	@$(MAKE) consume &
	@sleep 2
	@$(MAKE) produce &
