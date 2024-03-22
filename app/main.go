package main

import (
	"encoding/binary"
	"flag"
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
	for i := 0; i < int(m.DnsHeader.AnswerRecordCount); i++ {
		b = append(b, EncodeDomain(m.Answer[i].Name)...)
		b = binary.BigEndian.AppendUint16(b, m.Answer[i].Type)
		b = binary.BigEndian.AppendUint16(b, m.Answer[i].Class)
		b = binary.BigEndian.AppendUint32(b, m.Answer[i].TimeToLive)
		b = binary.BigEndian.AppendUint16(b, m.Answer[i].Length)
		b = append(b, m.Answer[i].Data...)
	}
	return b

}

func SetResponseFlag(request *Message) {
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
}

func ReadHeader(buf []byte, request *Message) {
	request.DnsHeader.PacketId = binary.BigEndian.Uint16(buf[:2])
	request.DnsHeader.Flag = binary.BigEndian.Uint16(buf[2:4])
	request.DnsHeader.QuestionCount = binary.BigEndian.Uint16(buf[4:6])
	request.DnsHeader.AnswerRecordCount = binary.BigEndian.Uint16(buf[6:8])
	request.DnsHeader.AuthorityRecordCount = binary.BigEndian.Uint16(buf[8:10])
	request.DnsHeader.AdditionalRecordCount = binary.BigEndian.Uint16(buf[10:12])

}

func ReadQuestion(buf []byte, request *Message) int {
	var offset int = 12
	for i := 0; i < int(request.DnsHeader.QuestionCount); i++ {
		question := Question{}
		question.Name, offset = DecodeDomain(buf, offset)
		question.Type = binary.BigEndian.Uint16(buf[offset : offset+2])
		offset += 2
		question.Class = binary.BigEndian.Uint16(buf[offset : offset+4])
		offset += 2
		request.Question = append(request.Question, question)
	}
	return offset
}

func ReadAnswer(buf []byte, request *Message, offset int) int {

	for i := 0; i < int(request.DnsHeader.AnswerRecordCount); i++ {
		answer := Answer{}
		answer.Name, offset = DecodeDomain(buf, offset)

		answer.Type = binary.BigEndian.Uint16(buf[offset : offset+2])
		offset += 2
		answer.Class = binary.BigEndian.Uint16(buf[offset : offset+2])
		offset += 2
		answer.TimeToLive = binary.BigEndian.Uint32(buf[offset : offset+4])
		offset += 4
		answer.Length = binary.BigEndian.Uint16(buf[offset : offset+2])
		offset += 2
		answer.Data = buf[offset : offset+int(answer.Length)]
		offset += int(answer.Length)
		request.Answer = append(request.Answer, answer)
	}
	return offset
}

func ForwardRequest(request []byte, rawAddress string) *Message {

	addr, err := net.ResolveUDPAddr("udp", rawAddress)
	if err != nil {
		fmt.Printf("error ResolveUDPAddr %s", err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Println("error DialUDP")
	}
	defer conn.Close()
	_, err = conn.Write(request)
	if err != nil {
		fmt.Println("error making forward request")
	}

	responseBuf := make([]byte, 512)
	size, _, err := conn.ReadFromUDP(responseBuf)
	if err != nil {
		fmt.Println("error reading forward request")
	}

	response := Message{}
	ReadHeader(responseBuf[:size], &response)
	qoffset := ReadQuestion(responseBuf[:size], &response)
	ReadAnswer(responseBuf[:size], &response, qoffset)
	// SetResponseFlag(&response)
	fmt.Println("f->", responseBuf[qoffset:size])
	fmt.Println("n->", response.Byte()[qoffset:size])
	return &response
}

func NewResponse(request *Message) {
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
}

func main() {

	resolverOption := flag.String("resolver", "", "DNS resolver address")
	flag.Parse()
	fmt.Println(*resolverOption)
	fmt.Println(len(*resolverOption))
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

		request := Message{}
		ReadHeader(buf[:size], &request)
		ReadQuestion(buf[:size], &request)
		if len(*resolverOption) > 0 {

			forwardResp := ForwardRequest(request.Byte(), *resolverOption)
			// request.DnsHeader = forwardResp.DnsHeader
			// request.Question = forwardResp.Question
			// request.Answer = forwardResp.Answer

			_, err = udpConn.WriteToUDP(forwardResp.Byte(), source)
			if err != nil {
				fmt.Println("Failed to send response:", err)
			}
			fmt.Printf("Request :%+v\n", forwardResp)
		} else {
			NewResponse(&request)
			request.DnsHeader.AnswerRecordCount = uint16(len(request.Answer))
			SetResponseFlag(&request)
			fmt.Printf("Request :%+v\n", request)
			_, err = udpConn.WriteToUDP(request.Byte(), source)
			if err != nil {
				fmt.Println("Failed to send response:", err)
			}
		}

		// request.DnsHeader.AnswerRecordCount = uint16(len(request.Answer))

	}
}

func DecodeDomain(buf []byte, offset int) (string, int) {
	labels := []string{}
	// originalOffset := offset

	for {
		var num int = int(buf[offset])
		offset++

		if num == 0 {
			break // End of the domain name
		}

		if num&0xC0 == 0xC0 {
			// The next byte is part of the pointer offset, so we combine it with the lower bits of the current byte
			pointer := int(num&0x3F)<<8 + int(buf[offset])
			offset++ // Move past the second byte of the pointer

			// Decode the domain part pointed to by the pointer. Note: We don't update 'offset' here because
			// it should continue from where the pointer was encountered.
			// 'DecodeDomain' is recursively called with the calculated pointer position.
			// We ignore the returned new offset because it's irrelevant outside the recursive context.
			part, _ := DecodeDomain(buf, pointer)
			labels = append(labels, part)
			break // A pointer always terminates the encoding of the current label.
		} else {
			// This is a standard label, not a pointer.
			label := string(buf[offset : offset+num])
			labels = append(labels, label)
			offset += num
		}
	}

	return strings.Join(labels, "."), offset
}
