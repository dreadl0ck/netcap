NAME=netcapture

build:
	@echo "Building $(NAME)..."
	@mkdir -p bin/
	@go build \
		-ldflags "-s -w" \
		-gcflags="all=-trimpath=$$GOPATH/src" \
		-asmflags="all=-trimpath=$$GOPATH/src" \
		-o bin/$(NAME) ./cmd

update:
	@dep ensure -v -update

check:
	@dep check

test:
	@go list ./... | xargs -n1 go test

clean:
	@rm -rf bin/

.PHONY: build
