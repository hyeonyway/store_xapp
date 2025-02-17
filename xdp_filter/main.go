//go:build amd64

package main

import "C"
import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"golang.org/x/sys/unix"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	// "golang.org/x/sys/unix"
)

const (
	NFPROTO_IPV4		= 0x2
	NF_INET_LOCAL_IN	= 0x1
)

func uint32ToIP(ipUint32 uint32) string {
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, ipUint32)
	ip := net.IP(ipBytes)
	return ip.String()
}

func reverseBytes(value uint16) uint16 {
    return (value>>8 | value<<8) & 0xFFFF
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 -type event bpf monitoring.c -- -I../headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Printf("loading objects: %s", err)
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			log.Printf("%+v", verifierErr)
		}
	}
	defer objs.Close()

	// ifaceName := "eth0" // 필요한 인터페이스 이름으로 변경
	// // ifaceName := "ens18"

    // iface, err := net.InterfaceByName(ifaceName)
    // if err != nil {
    //     log.Fatalf("Failed to get interface by name %s: %v", ifaceName, err)
    // }

	ifaceName := "eth0" 

    netnsPath := "/proc/2887335/ns/net" 

    newNs, err := os.Open(netnsPath)
    if err != nil {
        log.Fatalf("Failed to open target net namespace %s: %v", netnsPath, err)
    }
    defer newNs.Close()

    if err := unix.Setns(int(newNs.Fd()), unix.CLONE_NEWNET); err != nil {
        log.Fatalf("Failed to switch to target net namespace: %v", err)
    }

    iface, err := net.InterfaceByName(ifaceName)
    if err != nil {
        log.Fatalf("Failed to get interface by name %s: %v", ifaceName, err)
    }
    fmt.Printf("Interface found: %v\n", iface)

	xl, err := link.AttachXDP(link.XDPOptions{
		Program 	: objs.XdpFilter,
		Interface 	: iface.Index,
	})
	if err != nil {
		log.Printf("Attach XDP: %s", err)
	}
	defer xl.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		if err := xl.Close(); err != nil {
			log.Fatalf("closing netfilter : %s", err)
		}

		os.Exit(0)
	}()

	log.Println("Waiting for events..")

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		
		if err == nil {
			log.Printf("[INFO] Source IP Banned 1 Min!\n"+
				"\t Size : %d\n"+
				"\t Source : %s:%d", event.Size, uint32ToIP(event.Saddr), reverseBytes(event.Sport))
		}
	}
}