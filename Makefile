# Name of the output binary
BINARY_NAME=packetgo

# Default target
all: build run

# Build the Go application
build:
	go build -o $(BINARY_NAME) .

# Run the application with sudo
run: build
	sudo ./$(BINARY_NAME) "eno1"

# Clean up the binary
clean:
	rm -f $(BINARY_NAME)
