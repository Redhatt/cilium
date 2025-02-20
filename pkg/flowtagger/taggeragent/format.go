package taggeragent

type PacketTaggingKey struct {
	SourceID        string
	DestinationID   string
	SourcePort      uint16
	DestinationPort uint16
	TraceID         uint64
}
