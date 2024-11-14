package main

import (
	"log"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/shad0wcrawl3r/packetgo/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "packetgo",
	Short: "TCPDump in Go",
	Long:  `A simple TCPDUMP implementation in Go.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			return
		}
	},
}

func ExecuteCobra() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}

func init() {
	cobra.OnInitialize(utils.ParseConfigs())
	rootCmd.PersistentFlags().StringP("interface", "i", "eth0", "Interface to listen on")
	viper.BindPFlag("interface", rootCmd.PersistentFlags().Lookup("interface"))
}

func main() {
	ExecuteCobra()
	var handle *pcap.Handle
	var err error
	if handle, err = pcap.OpenLive(viper.GetViper().GetString("interface"), 65535, true, pcap.BlockForever); err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	for {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if packet == nil {
				continue
			}
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}
			tcp, _ := tcpLayer.(*layers.TCP)
			payload := string(tcp.Payload)
			if strings.HasPrefix(payload, "GET ") || strings.HasPrefix(payload, "POST ") ||
				strings.HasPrefix(payload, "HTTP/1.1") || strings.HasPrefix(payload, "HTTP/1.0") {

				log.Println("HTTP Packet Detected")

				// Extract headers and body from payload
				headersEnd := strings.Index(payload, "\r\n\r\n")
				if headersEnd != -1 {
					headers := payload[:headersEnd]
					body := payload[headersEnd+4:]

					log.Printf("HTTP Headers:\n%s\n", headers)
					log.Printf("HTTP Body:\n%s\n", body)
				} else {
					// No body found, print entire payload as headers
					log.Printf("HTTP Headers (No Body Detected):\n%s\n", payload)
				}
			}
		}
	}

	// defer utils.ParseConfigs()()
	// fmt.Println("Starting")
	// handler, err := pcap.OpenOffline("./capture.pcap")
	//
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//
	// defer handler.Close()
	//
	//	for {
	//		data, _, err := handler.ReadPacketData()
	//		if err != nil {
	//			log.Fatal(err)
	//		}
	//		packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
	//		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	//		if ethernetLayer == nil {
	//			log.Println("No Ethernet Layer Found")
	//			continue
	//		}
	//
	//		ipLayer := packet.Layer(layers.LayerTypeIPv4)
	//		if ipLayer == nil {
	//			log.Println("No IP Layer Found")
	//			continue
	//		}
	//
	//		tcpLayer := packet.Layer(layers.LayerTypeTCP)
	//		if tcpLayer == nil {
	//			log.Println("No TCP Layer Found")
	//			continue
	//		}
	//
	//		ip, _ := ipLayer.(*layers.IPv4)
	//		if ip.SrcIP.String() == "10.139.0.6" {
	//			continue
	//		}
	//		tcp, _ := tcpLayer.(*layers.TCP)
	//
	//		switch tcp.SrcPort {
	//		case 22:
	//			continue
	//		case 443:
	//			continue
	//		case 25061:
	//			continue
	//		}
	//		switch tcp.DstPort {
	//		case 22:
	//			continue
	//		case 443:
	//			continue
	//		case 25061:
	//			continue
	//		}
	//		// if tcp.SrcPort tcp.DstPort != 22 {
	//		log.Printf("%s:%d -> %s:%d ", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
	//		// TODO: Filter for HTTP Traffic
	//		// TODO: Alanyze HTTP Headers
	//		// TODO: Display HTTP Body
	//
	// }
}
