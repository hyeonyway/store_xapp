BPF_CLANG := clang
BPF_CFLAGS := -O2 -g -Wall -target bpf

all: build

build: main monitor.o

monitor.o: monitor.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c monitor.c -o monitor.o

main: main.go monitor.o
	go mod tidy
	go build -o main main.go

clean:
	rm -f main monitor.o
