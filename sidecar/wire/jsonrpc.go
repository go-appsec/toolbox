package wire

import "encoding/json"

// JSONRPCVersion is the protocol identifier carried in every message.
const JSONRPCVersion = "2.0"

// Message is the single on-wire JSON-RPC 2.0 envelope. Both peers send and
// receive Messages; the discriminators classify each one:
//   - request:      has id and method
//   - response:     has id, no method (carries result or error)
//   - notification: no id, has method
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

func (m *Message) IsRequest() bool      { return len(m.ID) > 0 && m.Method != "" }
func (m *Message) IsResponse() bool     { return len(m.ID) > 0 && m.Method == "" }
func (m *Message) IsNotification() bool { return len(m.ID) == 0 && m.Method != "" }
