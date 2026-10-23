.PHONY: build test vet clean run

BINARY=certkit

build:
	CGO_ENABLED=0 go build -o $(BINARY) ./cmd/certkit

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

run: build
	./$(BINARY)
