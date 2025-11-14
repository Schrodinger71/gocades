all: build

build:
	CGO_ENABLED=1 go build -o gocades 

clean:
	rm -f gocades || echo "no binary"
