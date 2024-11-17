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

func decodeHTTP(payload string) {
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

			if ipLayer := packet.NetworkLayer(); ipLayer != nil {
				ip, ok := ipLayer.(*layers.IPv4)
				if !ok {
					log.Println("Not an IPv4 packet")
					continue
				}
				proto, srcPort, dstPort := "", 0, 0
				if tcpLayer := packet.TransportLayer(); tcpLayer != nil {
					switch tcpLayer.LayerType() {
					case layers.LayerTypeTCP:
						proto = "TCP"
						tcp, _ := tcpLayer.(*layers.TCP)
						srcPort, dstPort = int(tcp.SrcPort), int(tcp.DstPort)
					case layers.LayerTypeUDP:
						proto = "UDP"
						udp, _ := tcpLayer.(*layers.UDP)
						srcPort, dstPort = int(udp.SrcPort), int(udp.DstPort)
					default:
						proto = "UNKNOWN"
						srcPort, dstPort = 0, 0
					}

					log.Printf("%s:%d --%s--> %s:%d", ip.SrcIP.String(), srcPort, proto, ip.DstIP.String(), dstPort)
				}

			}

		}
	}
}
