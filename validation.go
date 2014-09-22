package radius

import (
	"bytes"
	"crypto"
	_ "crypto/md5"
	"errors"
	"fmt"
	"net"
	"time"
)

type AttributeDataType uint8

const (
	_                         = iota
	TEXT    AttributeDataType = iota
	STRING  AttributeDataType = iota
	ADDRESS AttributeDataType = iota
	VALUE   AttributeDataType = iota
	INTEGER AttributeDataType = iota
	TIME    AttributeDataType = iota
)

const (
	UNLIMITED = -1
)

type Validation struct {
	Kind      AttributeDataType
	MinLength int
	MaxLength int //if < 0 unlimited
	Decode    func(p *Packet, attr *AVP) error
}

func (a AVP) Binary() ([]byte, error)    { return a.Value, nil }
func (a AVP) Address() (net.Addr, error) { return nil, nil }
func (a AVP) Integer() (uint32, error)   { return 0, nil }
func (a AVP) Time() (time.Time, error)   { return time.Time{}, nil }
func (a AVP) Text() (string, error)      { return "", nil }

func (v Validation) Validate(p *Packet, attr *AVP) error {

	if len(attr.Value) < v.MinLength {
		return errors.New("value too short")
	}

	if v.MaxLength != UNLIMITED && len(attr.Value) > v.MaxLength {
		return fmt.Errorf("value too long: test %d against %d", len(attr.Value), v.MaxLength)
	}

	switch v.Kind {
	case TEXT:
	case STRING:
	case ADDRESS:
	case VALUE:
	case INTEGER:
	case TIME:
	}

	if v.Decode != nil {
		return v.Decode(p, attr)
	}
	return nil
}

func DecodeUserPassword(p *Packet, a *AVP) error {
	//Decode password. XOR against md5(p.server.secret+Authenticator)
	secAuth := append([]byte(nil), []byte(p.server.secret)...)
	secAuth = append(secAuth, p.Authenticator[:]...)
	m := crypto.Hash(crypto.MD5).New()
	m.Write(secAuth)
	md := m.Sum(nil)
	pass := a.Value
	if len(pass) == 16 {
		for i := 0; i < len(pass); i++ {
			pass[i] = pass[i] ^ md[i]
		}
		a.Value = bytes.TrimRight(pass, string([]rune{0}))
		return nil
	}
	return errors.New("not implemented for password > 16")
}

var validation = map[AttributeType]Validation{
	UserName:               {STRING, 1, UNLIMITED, nil},
	UserPassword:           {STRING, 16, 128, DecodeUserPassword},
	CHAPPassword:           {STRING, 17, 17, nil},
	NASIPAddress:           {ADDRESS, 4, 4, nil},
	NASPort:                {VALUE, 4, 4, nil},
	MessageAuthenticator:   {STRING, 1, UNLIMITED, nil},
	ServiceType:            {STRING, 1, UNLIMITED, nil},
	FramedProtocol:         {STRING, 1, UNLIMITED, nil},
	FramedIPAddress:        {STRING, 1, UNLIMITED, nil},
	FramedIPNetmask:        {},
	FramedRouting:          {},
	FilterId:               {},
	FramedMTU:              {},
	FramedCompression:      {},
	LoginIPHost:            {},
	LoginService:           {},
	LoginTCPPort:           {},
	ReplyMessage:           {},
	CallbackNumber:         {},
	CallbackId:             {},
	FramedRoute:            {},
	FramedIPXNetwork:       {},
	State:                  {},
	Class:                  {},
	VendorSpecific:         {STRING, 1, UNLIMITED, nil},
	SessionTimeout:         {STRING, 1, UNLIMITED, nil},
	IdleTimeout:            {STRING, 1, UNLIMITED, nil},
	TerminationAction:      {},
	CalledStationId:        {STRING, 1, UNLIMITED, nil},
	CallingStationId:       {STRING, 1, UNLIMITED, nil},
	NASIdentifier:          {STRING, 1, UNLIMITED, nil},
	ProxyState:             {},
	LoginLATService:        {},
	LoginLATNode:           {},
	LoginLATGroup:          {},
	FramedAppleTalkLink:    {},
	FramedAppleTalkNetwork: {},
	FramedAppleTalkZone:    {},
	AcctStatusType:         {STRING, 1, UNLIMITED, nil},
	AcctDelayTime:          {STRING, 1, UNLIMITED, nil},
	AcctInputOctets:        {STRING, 1, UNLIMITED, nil},
	AcctOutputOctets:       {STRING, 1, UNLIMITED, nil},
	AcctSessionId:          {STRING, 1, UNLIMITED, nil},
	AcctAuthentic:          {STRING, 1, UNLIMITED, nil},
	AcctSessionTime:        {STRING, 1, UNLIMITED, nil},
	AcctInputPackets:       {STRING, 1, UNLIMITED, nil},
	AcctOutputPackets:      {STRING, 1, UNLIMITED, nil},
	AcctTerminateCause:     {STRING, 1, UNLIMITED, nil},
	AcctMultiSessionId:     {},
	AcctLinkCount:          {STRING, 1, UNLIMITED, nil},
	EventTimestamp:         {STRING, 1, UNLIMITED, nil},

	CHAPChallenge:       {STRING, 1, UNLIMITED, nil},
	NASPortType:         {STRING, 1, UNLIMITED, nil},
	NASPortId:           {STRING, 1, UNLIMITED, nil},
	LocationInformation: {STRING, 1, UNLIMITED, nil},
	LocationData:        {STRING, 1, UNLIMITED, nil},
	PortLimit:           {},
	LoginLATPort:        {},
	AcctInputGigawords:  {STRING, 1, UNLIMITED, nil},
	AcctOutputGigawords: {STRING, 1, UNLIMITED, nil},
	ConnectInfo:         {STRING, 1, UNLIMITED, nil},
}

/*
AccessRequest      PacketCode = 1
MUST NAS-IP-Address AND/OR NAS-Identifier

     User-Password XOR CHAP-Password XOR State XOR someother authentication





AccessAccept       PacketCode = 2
AccessReject       PacketCode = 3


AccountingRequest  PacketCode = 4
AccountingResponse PacketCode = 5
AccessChallenge    PacketCode = 11

*/
