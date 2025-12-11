package pkg

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
)

type Protocol string

const (
	ProtocolTCP  Protocol = "TCP"
	ProtocolUDP  Protocol = "UDP"
	ProtocolICMP Protocol = "ICMP"
)

type NetflowPacket struct {
	IP        string `json:"ip"`
	Protocol  `json:"protocol"`
	ByteSum   int64  `json:"byte_sum"`
	ISP       string `json:"isp"`
	Country   string `json:"country"`
	Direction string `json:"direction"`
}

func MarshalNetflowBatch(batch []NetflowPacket) ([]byte, error) {
	// as compressed gob bytes
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := gob.NewEncoder(gz)
	if err := enc.Encode(batch); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func UnmarshalNetflowBatch(data []byte) ([]NetflowPacket, error) {
	var batch []NetflowPacket
	buf := bytes.NewBuffer(data)
	gz, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	dec := gob.NewDecoder(gz)
	if err := dec.Decode(&batch); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return batch, nil
}
