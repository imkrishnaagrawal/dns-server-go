package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

const HEADER_SIZE = 12

const (
	FlagQueryIndicator      = 1 << 15 // QR
	FlagOperationCode       = 1 << 11 // OPCODE
	FlagAuthoritativeAnswer = 1 << 10 // AA
	FlagTruncation          = 1 << 9  // TC
	FlagRecursionDesired    = 1 << 8  // RD
	FlagRecursionAvailable  = 1 << 7  // RA
	FlagReserved            = 1 << 4  // RZ
	FlagResponseCode        = 1 << 0  // RCODE
)

type DnsHeader struct {
	PacketId              uint16 // ID
	Flag                  uint16 //
	QuestionCount         uint16 // QDCOUNT
	AnswerRecordCount     uint16 // ANCOUNT
	AuthorityRecordCount  uint16 // NSCOUNT
	AdditionalRecordCount uint16 // ARCOUNT
}

type Message struct {
	DnsHeader
}

func NewMessage() Message {

	return Message{

		DnsHeader: DnsHeader{
			PacketId:              1234,
			Flag:                  FlagQueryIndicator,
			QuestionCount:         0,
			AnswerRecordCount:     0,
			AuthorityRecordCount:  0,
			AdditionalRecordCount: 0,
		},
	}

}

func (m Message) Byte() []byte {

	b := make([]byte, HEADER_SIZE)
	binary.BigEndian.PutUint16(b[0:2], m.DnsHeader.PacketId)
	binary.BigEndian.PutUint16(b[2:4], m.DnsHeader.Flag)
	binary.BigEndian.PutUint16(b[4:6], m.DnsHeader.QuestionCount)
	binary.BigEndian.PutUint16(b[6:8], m.DnsHeader.AnswerRecordCount)
	binary.BigEndian.PutUint16(b[8:10], m.DnsHeader.AuthorityRecordCount)
	binary.BigEndian.PutUint16(b[10:12], m.DnsHeader.AdditionalRecordCount)
	return b

}

func (m Message) Read([]byte) {

	b := make([]byte, HEADER_SIZE)
	binary.BigEndian.PutUint16(b[0:2], m.DnsHeader.PacketId)
	binary.BigEndian.PutUint16(b[2:4], m.DnsHeader.Flag)
	binary.BigEndian.PutUint16(b[4:6], m.DnsHeader.QuestionCount)
	binary.BigEndian.PutUint16(b[6:8], m.DnsHeader.AnswerRecordCount)
	binary.BigEndian.PutUint16(b[8:10], m.DnsHeader.AuthorityRecordCount)
	binary.BigEndian.PutUint16(b[10:12], m.DnsHeader.AdditionalRecordCount)
	// return b

}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
		fmt.Println(size)
		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s:: %s\n", size, source, receivedData)

		packetId := binary.BigEndian.Uint16(buf[:2])
		// Create an empty response
		response := NewMessage()
		response.PacketId = packetId

		_, err = udpConn.WriteToUDP(response.Byte(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
