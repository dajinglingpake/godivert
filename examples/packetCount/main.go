package main

import (
	godivert "examples"
	"examples/header"
	"fmt"
	"log"
	"os"
	"time"
)

var icmpv4, icmpv6, udp, tcp, unknown, served, inbound, outbound uint

func checkPacket(wd *godivert.WinDivertHandle, packetChan <-chan *godivert.Packet) {
	for packet := range packetChan {
		countPacket(packet)
		wd.Send(packet)
	}
}

func countPacket(packet *godivert.Packet) {
	if packet.Addr.Data&0x1 == 1 {
		inbound++
	} else {
		outbound++
	}
	served++
	switch packet.NextHeaderType() {
	case header.ICMPv4:
		icmpv4++
	case header.ICMPv6:
		icmpv6++
	case header.TCP:
		tcp++
	case header.UDP:
		udp++
	default:
		unknown++
	}
}

// 自动切换工作目录
func init() {
	// 程序所在目录
	var execDir = "C:\\Users\\dajinglingpake\\GolandProjects\\godivert\\examples"
	pwd, _ := os.Getwd()
	fmt.Println("开始工作目录", pwd)
	if pwd == execDir {
		fmt.Println("不需要切换工作目录")
		return
	}
	fmt.Println("切换工作目录到", execDir)
	if err := os.Chdir(execDir); err != nil {
		log.Fatal(err)
	}
	pwd, _ = os.Getwd()
	fmt.Println("切换后工作目录:", pwd)
}

func main() {
	godivert.LoadDLL("./WinDivert-2.2.2-A/x64/WinDivert.dll", "./WinDivert-2.2.2-A/x86/WinDivert.dll")

	winDivert, err := godivert.NewWinDivertHandle("true")
	if err != nil {
		panic(err)
	}

	fmt.Println("Starting")

	packetChan, err := winDivert.Packets()
	if err != nil {
		panic(err)
	}
	defer winDivert.Close()

	n := 50
	for i := 0; i < n; i++ {
		go checkPacket(winDivert, packetChan)
	}

	time.Sleep(15 * time.Second)

	fmt.Println("Stopping...")

	fmt.Printf("Served: %d packets\n", served)

	fmt.Printf("ICMPv4=%d ICMPv6=%d UDP=%d TCP=%d Unknown=%d Inbound=%d Outbound=%d", icmpv4, icmpv6, udp, tcp, unknown, inbound, outbound)
}
