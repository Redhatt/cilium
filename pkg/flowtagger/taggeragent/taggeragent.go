package taggeragent

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
)

const (
	tagMapName       = "traffic_tag_map"
	pinnedMapPath    = "/sys/fs/bpf"
	tagMapKeySize    = uint32(10)
	tagMapValueSize  = uint32(9)
	tagMapMaxEntries = 1024
)

type TrafficTagKey struct {
	SourceIP   uint32
	DestIP     uint32
	SourcePort uint16
	DestPort   uint16
}

type TrafficTagValue struct {
	TraceID      uint64
	IPOptionType uint8
}

// function to convert string IP to uint32 (big-endian)
func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address format: %s", ipStr)
	}

	ip4 := ip.To4()
	if ip4 != nil {
		return binary.BigEndian.Uint32(ip.To4()), nil
	}
	return 0, fmt.Errorf("only IPv4 addresses are supported")
}

type TaggingAgent struct {
	mapName       string
	pinnedMapPath string
	MaxEntries    uint32
	KeySize       uint32
	ValueSize     uint32
}

func NewDefaultTaggingAgent() *TaggingAgent {
	return &TaggingAgent{
		mapName:       tagMapName,
		pinnedMapPath: pinnedMapPath,
		MaxEntries:    tagMapMaxEntries,
		KeySize:       tagMapKeySize,
		ValueSize:     tagMapValueSize,
	}
}

func (t *TaggingAgent) getMapSpec() *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       t.mapName,
		Type:       ebpf.Hash,
		KeySize:    t.KeySize,
		ValueSize:  t.ValueSize,
		MaxEntries: t.MaxEntries,
		Pinning:    ebpf.PinByName,
	}
}

func (t *TaggingAgent) AddKey(packetTaggingKey PacketTaggingKey) error {
	sourceIP, err := ipToUint32(packetTaggingKey.SourceID)
	if err != nil {
		return err
	}

	destinationIP, err := ipToUint32(packetTaggingKey.DestinationID)
	if err != nil {
		return err
	}

	pinnedMapPath := t.pinnedMapPath
	options := ebpf.MapOptions{
		PinPath: pinnedMapPath,
	}

	mapSpec := t.getMapSpec()
	mapFd, err := ebpf.NewMapWithOptions(mapSpec, options)
	if err != nil {
		return err
	}
	defer mapFd.Close()

	key := TrafficTagKey{
		SourceIP:   sourceIP,
		DestIP:     destinationIP,
		SourcePort: packetTaggingKey.SourcePort,
		DestPort:   packetTaggingKey.DestinationPort,
	}
	value := TrafficTagValue{TraceID: packetTaggingKey.TraceID, IPOptionType: 1}

	err = mapFd.Update(unsafe.Pointer(&key), unsafe.Pointer(&value), ebpf.UpdateAny)
	if err != nil {
		return err
	}

	var result TrafficTagValue
	err = mapFd.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&result))
	if err != nil {
		return err
	}
	return nil
}

func (t *TaggingAgent) DeleteKey(packetTaggingKey PacketTaggingKey) error {
	sourceIP, err := ipToUint32(packetTaggingKey.SourceID)
	if err != nil {
		return err
	}

	destinationIP, err := ipToUint32(packetTaggingKey.DestinationID)
	if err != nil {
		return err
	}

	pinnedMapPath := t.pinnedMapPath
	options := ebpf.MapOptions{
		PinPath: pinnedMapPath,
	}

	mapSpec := t.getMapSpec()
	mapFd, err := ebpf.NewMapWithOptions(mapSpec, options)
	if err != nil {
		return err
	}
	defer mapFd.Close()

	key := TrafficTagKey{
		SourceIP:   sourceIP,
		DestIP:     destinationIP,
		SourcePort: packetTaggingKey.SourcePort,
		DestPort:   packetTaggingKey.DestinationPort,
	}
	err = mapFd.Delete(unsafe.Pointer(&key))
	if err != nil {
		return err
	}
	return nil
}
