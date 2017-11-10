package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	pcapFile    = "/home/emrecan/go/src/github.com/emrechan/packetIpMasker/20171031_L16_Pazar_Wireshark_1st-session.pcap"
	handle      *pcap.Handle
	err         error
	snapshotLen uint32 = 65536
	portList    []string
	ipList      = make(map[string]net.IP, 1)
	buffer      gopacket.SerializeBuffer
	options     gopacket.SerializeOptions
	usage       = `usage: ./packetIpParser -i <input.pcap> -o <output.pcap>`
)

// config.json structure
// protocol field is put for later use. Currently
// it is not implemented...
type config struct {
	Protocol string            `json:"protocol"`
	Masks    map[string]string `json:"masks"`
}

// Read config.json and get the masking map
func getConfig() config {
	raw, err := ioutil.ReadFile("./config.json")
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	var c config
	json.Unmarshal(raw, &c)
	return c
}

func isIPInIPList(currentIP net.IP, ipList map[string]net.IP) bool {
	if _, ok := ipList[currentIP.String()]; ok {
		return true
	}
	return false
}

func createNewPacket(
	ethernetLayer *layers.Ethernet,
	ipv4Layer *layers.IPv4,
	tcpLayer *layers.TCP,
	payload []byte,
) error {
	// This is needed to recalculate the checksum
	// of the new packet
	tcpLayer.SetNetworkLayerForChecksum(ipv4Layer)

	if isIPInIPList(ipv4Layer.SrcIP, ipList) {
		ipv4Layer.SrcIP = ipList[ipv4Layer.SrcIP.String()]

	}
	if isIPInIPList(ipv4Layer.DstIP, ipList) {
		ipv4Layer.DstIP = ipList[ipv4Layer.DstIP.String()]
	}

	err = gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipv4Layer,
		tcpLayer,
		gopacket.Payload(payload))

	return err
}

func main() {
	inputFile := flag.String("i", "", "input file")
	outputFile := flag.String("o", "", "output file")
	var filter string

	flag.StringVar(&filter, "f", "", "filter to use")

	flag.Parse()

	if *inputFile == "" || *outputFile == "" {
		fmt.Println(usage)
		os.Exit(1)
	}

	buffer = gopacket.NewSerializeBuffer()
	options = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
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

	// Open output pcap file and write header
	f, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer f.Close()

	config := getConfig()
	for k, v := range config.Masks {
		if ip := net.ParseIP(v); ip != nil {
			ipList[k] = ip
			fmt.Printf("%s -> %s\n", k, v)
		} else {
			fmt.Printf("%s is not a valid IP address! Skipping...\n", v)
		}
	}
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet, w)
	}
}

func printPacketInfo(packet gopacket.Packet, w *pcapgo.Writer) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		// Let's see if the packet is IP (even though the ether type told us)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				// Payload definitions
				var p []byte
				// If packet contains any payload get it
				// Otherwise payload is nil
				if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
					p = applicationLayer.Payload()
				}
				// Create a new packet using the decoded packet
				// Do not write to output file if there is any error
				if err = createNewPacket(ethernetLayer.(*layers.Ethernet), ipLayer.(*layers.IPv4), tcpLayer.(*layers.TCP), p); err != nil {
					fmt.Println(err)
					return
				}
				// Write the new packet with the metadata of the
				// captured packet
				if err = w.WritePacket(packet.Metadata().CaptureInfo, buffer.Bytes()); err != nil {
					fmt.Println(err)
				}
			}
		}
	}
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
