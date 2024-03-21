package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const HEADER_SIZE = 12

const (
	CLASS_IN = 1 //the Internet
	CLASS_CS = 2 //the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	CLASS_CH = 3 // the CHAOS class
	CLASS_HS = 4 // Hesiod [Dyer 87]
)

const (
	TYPE_A     = 1  // a host address
	TYPE_NS    = 2  // an authoritative name server
	TYPE_MD    = 3  // a mail destination (Obsolete - use MX)
	TYPE_MF    = 4  // a mail forwarder (Obsolete - use MX)
	TYPE_CNAME = 5  // the canonical name for an alias
	TYPE_SOA   = 6  // marks the start of a zone of authority
	TYPE_MB    = 7  // a mailbox domain name (EXPERIMENTAL)
	TYPE_MG    = 8  // a mail group member (EXPERIMENTAL)
	TYPE_MR    = 9  // a mail rename domain name (EXPERIMENTAL)
	TYPE_NULL  = 10 // a null RR (EXPERIMENTAL)
	TYPE_WKS   = 11 // a well known service description
	TYPE_PTR   = 12 // a domain name pointer
	TYPE_HINFO = 13 // host information
	TYPE_MINFO = 14 // mailbox or mail list information
	TYPE_MX    = 15 // mail exchange
	TYPE_TXT   = 16 // text strings
)

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

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type Answer struct {
	Name       string
	Type       uint16
	Class      uint16
	TimeToLive uint32
	Length     uint16
	Data       []byte
}

func EncodeDomain(name string) []byte {
	b := make([]byte, 0)
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	return b
}

type Message struct {
	DnsHeader
	Question
	Answer
}

func NewMessage(Label string, data []byte) Message {

	return Message{

		DnsHeader: DnsHeader{
			PacketId:              1234,
			Flag:                  FlagQueryIndicator,
			QuestionCount:         1,
			AnswerRecordCount:     1,
			AuthorityRecordCount:  0,
			AdditionalRecordCount: 0,
		},
		Question: Question{
			Name:  Label,
			Type:  TYPE_A,
			Class: CLASS_IN,
		},
		Answer: Answer{
			Name:       Label,
			Type:       TYPE_A,
			Class:      CLASS_IN,
			TimeToLive: 60,
			Length:     uint16(len(data)),
			Data:       data,
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

	b = append(b, EncodeDomain(m.Question.Name)...)
	b = binary.BigEndian.AppendUint16(b, m.Question.Type)
	b = binary.BigEndian.AppendUint16(b, m.Question.Class)

	b = append(b, EncodeDomain(m.Answer.Name)...)
	b = binary.BigEndian.AppendUint16(b, m.Answer.Type)
	b = binary.BigEndian.AppendUint16(b, m.Answer.Class)
	b = binary.BigEndian.AppendUint32(b, m.Answer.TimeToLive)
	b = binary.BigEndian.AppendUint16(b, m.Answer.Length)
	b = append(b, m.Answer.Data...)
	return b

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

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s:: %s\n", size, source, receivedData)

		packetId := binary.BigEndian.Uint16(buf[:2])
		qCount := binary.BigEndian.Uint16(buf[4:6])
		reader := bytes.NewReader(buf[12:])
		domainName := DecodeDomain(reader)

		var qtype uint16
		var qclass uint16
		binary.Read(reader, binary.BigEndian, &qtype)
		binary.Read(reader, binary.BigEndian, &qclass)

		fmt.Printf("QCount :%d\n", qCount)
		fmt.Printf("Domain :%s\n", domainName)
		fmt.Printf("QType :%d\n", qtype)
		fmt.Printf("QClass :%d\n", qclass)

		response := NewMessage(domainName, []byte("\x08\x08\x08\x08"))
		response.DnsHeader.PacketId = packetId
		response.DnsHeader.QuestionCount = qCount
		response.Question.Type = qtype
		response.Question.Class = qclass

		_, err = udpConn.WriteToUDP(response.Byte(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

func DecodeDomain(reader *bytes.Reader) string {
	labels := []string{}
	var num uint8
	for {
		err := binary.Read(reader, binary.BigEndian, &num)
		if err != nil {
			fmt.Println("Failed To Read Label Size", err)
		}
		if num <= 0 {
			break
		}
		label := make([]byte, num)
		err = binary.Read(reader, binary.BigEndian, &label)
		if err != nil {
			fmt.Println("Failed To Read Label", err)
		}
		labels = append(labels, string(label))
	}

	return strings.Join(labels, ".")

}
