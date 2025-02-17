package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
)

// 인터페이스 이름 설정 (필요한 경우 변경)
const ifaceName = "eth0@if74"

// main 함수
func main() {
    // eBPF 오브젝트 로드
    objs := struct {
        MonitorSctpPacket *ebpf.Program `ebpf:"monitor_sctp_packet"`
        Events            *ebpf.Map     `ebpf:"events"`
    }{}
    spec, err := ebpf.LoadCollectionSpec("monitor.o")
    if err != nil {
        log.Fatalf("loading collection spec: %v", err)
    }
    coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
    if err != nil {
        log.Fatalf("creating new collection: %v", err)
    }
    defer coll.Close()
    objs.MonitorSctpPacket = coll.Programs["monitor_sctp_packet"]
    objs.Events = coll.Maps["events"]

    // 인터페이스 인덱스 가져오기
    iface, err := net.InterfaceByName(ifaceName)
    if err != nil {
        log.Fatalf("failed to find interface %s: %v", ifaceName, err)
    }

    // XDP 프로그램을 인터페이스에 연결
    lnk, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.MonitorSctpPacket,
        Interface: iface.Index,
        Flags:     link.XDPGenericMode,
    })
    if err != nil {
        log.Fatalf("attaching XDP program: %v", err)
    }
    defer lnk.Close()

    // PERF 이벤트 리더 생성
    rd, err := perf.NewReader(objs.Events, os.Getpagesize())
    if err != nil {
        log.Fatalf("creating perf reader: %v", err)
    }
    defer rd.Close()

    fmt.Println("Monitoring SCTP packet lengths on", ifaceName)

    // 종료 시그널 처리
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigs
        fmt.Println("\nExiting...")
        os.Exit(0)
    }()

    // 이벤트 읽기 루프
    for {
        record, err := rd.Read()
        if err != nil {
            if err == perf.ErrClosed {
                break
            }
            log.Printf("reading from perf event: %v", err)
            continue
        }

        if record.LostSamples > 0 {
            log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
            continue
        }

        // 패킷 길이 추출
        var packetLength uint32
        if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &packetLength); err != nil {
            log.Printf("binary read error: %v", err)
            continue
        }
        fmt.Printf("Captured SCTP packet length: %d bytes\n", packetLength)
    }
}
