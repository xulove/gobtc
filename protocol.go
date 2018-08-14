package wire
// BitcoinNet represents which bitcoin network a message belongs to.
type BitcoinNet uint32

// Constants used to indicate the message bitcoin network. 
const (
	MainNet  BitcoinNet = 0xd9b4bef9
	TestNet  BitcoinNet = 0xdab5bffa
	TestNet3 BitcoinNet = 0x0709110b
)