package main

import (
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
	Question []Question
	Answer   []Answer
}

func (m Message) Byte() []byte {

	b := make([]byte, HEADER_SIZE)
	binary.BigEndian.PutUint16(b[0:2], m.DnsHeader.PacketId)
	binary.BigEndian.PutUint16(b[2:4], m.DnsHeader.Flag)
	binary.BigEndian.PutUint16(b[4:6], m.DnsHeader.QuestionCount)
	binary.BigEndian.PutUint16(b[6:8], m.DnsHeader.AnswerRecordCount)
	binary.BigEndian.PutUint16(b[8:10], m.DnsHeader.AuthorityRecordCount)
	binary.BigEndian.PutUint16(b[10:12], m.DnsHeader.AdditionalRecordCount)

	for i := 0; i < int(m.DnsHeader.QuestionCount); i++ {
		b = append(b, EncodeDomain(m.Question[i].Name)...)
		b = binary.BigEndian.AppendUint16(b, m.Question[i].Type)
		b = binary.BigEndian.AppendUint16(b, m.Question[i].Class)
	}
	for i := 0; i < int(m.DnsHeader.QuestionCount); i++ {
		b = append(b, EncodeDomain(m.Answer[i].Name)...)
		b = binary.BigEndian.AppendUint16(b, m.Answer[i].Type)
		b = binary.BigEndian.AppendUint16(b, m.Answer[i].Class)
		b = binary.BigEndian.AppendUint32(b, m.Answer[i].TimeToLive)
		b = binary.BigEndian.AppendUint16(b, m.Answer[i].Length)
		b = append(b, m.Answer[i].Data...)
	}
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
		_, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		request := Message{
			Question: []Question{},
		}
		request.DnsHeader.PacketId = binary.BigEndian.Uint16(buf[:2])
		request.DnsHeader.Flag = binary.BigEndian.Uint16(buf[2:4])
		request.DnsHeader.QuestionCount = binary.BigEndian.Uint16(buf[4:6])
		request.DnsHeader.AnswerRecordCount = binary.BigEndian.Uint16(buf[6:8])
		request.DnsHeader.AuthorityRecordCount = binary.BigEndian.Uint16(buf[8:10])
		request.DnsHeader.AdditionalRecordCount = binary.BigEndian.Uint16(buf[10:12])

		var offset int = 12
		for i := 0; i < int(request.DnsHeader.QuestionCount); i++ {
			question := Question{}
			question.Name, offset = DecodeDomain(buf, offset)
			question.Type = binary.BigEndian.Uint16(buf[offset : offset+2])
			offset += 2
			question.Class = binary.BigEndian.Uint16(buf[offset : offset+4])
			offset += 2
			requestOpcode := request.DnsHeader.Flag >> 11 & 0xF
			responseOpcode := requestOpcode << 11
			requestRecursionDesired := request.DnsHeader.Flag >> 8 & 0x1
			responseRecursionDesired := requestRecursionDesired << 8
			var RCodeFlag uint16
			if requestOpcode == 0 {
				RCodeFlag = 0
			} else {
				RCodeFlag = 4
			}

			request.DnsHeader.Flag = FlagQueryIndicator | responseOpcode | responseRecursionDesired | RCodeFlag
			request.Question = append(request.Question, question)
		}
		for i := 0; i < int(request.DnsHeader.QuestionCount); i++ {
			data := []byte("\x08\x08\x08\x08")
			answer := Answer{}
			answer.Name = request.Question[i].Name
			answer.Type = request.Question[i].Type
			answer.Class = request.Question[i].Class
			answer.TimeToLive = 60
			answer.Length = uint16(len(data))
			answer.Data = data
			request.Answer = append(request.Answer, answer)
		}
		request.DnsHeader.AnswerRecordCount = uint16(len(request.Answer))

		fmt.Printf("Request :%+v\n", request)
		_, err = udpConn.WriteToUDP(request.Byte(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

func DecodeDomain(buf []byte, offset int) (string, int) {
	labels := []string{}

	for {
		var num int = int(buf[offset])
		offset += 1
		if num <= 0 {
			break
		} else if num&0xC0 == 0xC0 {
			// offset += 1
			pointer := int(buf[offset])
			fmt.Println(int(buf[offset]), int(buf[offset+1]))
			offset = int(num&0x3F)<<8 + pointer
			var name string
			name, offset = DecodeDomain(buf, offset)
			labels = append(labels, name)

		} else {
			label := buf[offset : offset+num]
			labels = append(labels, string(label))
			offset += num
		}

	}
	return strings.Join(labels, "."), offset

}
