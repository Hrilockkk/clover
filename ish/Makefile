.PHONY: all build clean

all: build

LDFLAGS = -s -w
GOFLAGS = -trimpath

build:
	@echo "Building scanner..."
	go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o clover.exe .
	@echo "Building server..."
	go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o server.exe ./server
	@echo "Done."

clean:
	rm -f clover.exe server.exe
