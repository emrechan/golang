package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	handle      *pcap.Handle
	err         error
	snapshotLen uint32 = 65536
	ipList             = make(map[string]net.IP, 1)
)

func main() {
	inputFile := flag.String("i", "", "input file")
	var filter string

	flag.StringVar(&filter, "f", "", "filter to use")

	flag.Parse()

	if *inputFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	if filter != "" {

	}

	// Open file instead of device
	handle, err = pcap.OpenOffline(*inputFile)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer handle.Close()

	if filter != "" {
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}

	var keys []string

	for k := range ipList {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		fmt.Printf("\"%s\":\"%s\"\n", k, k)
	}
}

func printPacketInfo(packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		// Let's see if the packet is IP (even though the ether type told us)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			ipList[ip.DstIP.String()] = ip.DstIP
			ipList[ip.SrcIP.String()] = ip.SrcIP
		}
	}
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
