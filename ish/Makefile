.PHONY: all build clean

all: build

LDFLAGS = -s -w

build:
	@echo "Building scanner..."
	go build -ldflags="$(LDFLAGS)" -o clover.exe .
	@echo "Building server..."
	go build -ldflags="$(LDFLAGS)" -o server.exe ./server
	@echo "Done."

clean:
	rm -f clover.exe server.exe
