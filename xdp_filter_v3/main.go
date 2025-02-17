//go:build amd64

package main

import "C"
import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
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

	ifaceName := "veth6875ee86" // 필요한 인터페이스 이름으로 변경
	// ifaceName := "cni0"
    iface, err := net.InterfaceByName(ifaceName)
    if err != nil {
        log.Fatalf("Failed to get interface by name %s: %v", ifaceName, err)
    }

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
			log.Printf("[INFO] Packet Blocked\n"+
				"\t Size : %d\n"+
				"\t Source IP : %s", event.Size, uint32ToIP(event.Saddr))
		}
	}
}