package wire

const (
	commandSize       = 12
	maxMessagePayload = (1024 * 1024 * 32) //32MB
)
const (
	cmdVersion    = "version"
	cmdVerAck     = "verack"
	cmdGetAddr    = "getaddr"
	cmdAddr       = "addr"
	cmdGetBlocks  = "getblocks"
	cmdInv        = "inv"
	cmdGetData    = "getdata"
	cmdNotFound   = "notfound"
	cmdBlock      = "block"
	cmdTx         = "tx"
	cmdGetHeaders = "getheaders"
	cmdHeaders    = "headers"
	cmdPing       = "ping"
	cmdPong       = "pong"
	cmdAlert      = "alert"
	cmdMemPool    = "mempool"
)
//版本啦，请求区块啦等都是消息，都是这个Message接口的实现
type Message interface {
	BtcDecode(io.Reader, uint32) error
	BtcEncode(io.Writer, uint32) error
	Command() string
	MaxPayloadLength(uint32) uint32
}
//根据command创建一个空的消息体
func makeEmptyMessage(command string)(Message ,error){
	var msg Message
	switch command{
		//这个就是版本消息
		case cmdVersion:
		msg = &MsgVersion{}
		//这是版本请求的的应答消息
		case CmdVerAck:
		msg =&MsgVerAck{}
		case cmdGetAddr:
		msg = &MsgGetAddr{}
		case cmdAddr:
		msg = &MsgAddr{}
		case cmdGetBlocks:
		msg = &MsgGetBlocks{}

		case cmdBlock:
			msg = &MsgBlock{}

		case cmdInv:
			msg = &MsgInv{}

		case cmdGetData:
			msg = &MsgGetData{}

		case cmdNotFound:
			msg = &MsgNotFound{}

		case cmdTx:
			msg = &MsgTx{}

		case cmdPing:
			msg = &MsgPing{}

		case cmdPong:
			msg = &MsgPong{}

		case cmdGetHeaders:
			msg = &MsgGetHeaders{}

		case cmdHeaders:
			msg = &MsgHeaders{}

		default:
			return nil, fmt.Errorf("unhandled command [%s]", command)
		}
		return msg, nil
		
	}
}
//给所有协议的消息定义了一个头结构体
type messageHeader struct{
	magic BitcoinNet //4byte
	command string  //12byte
	length uint32   //4byte
	checksum [4]byte//4byte
}
func readMessageHeader(r io.Reader)(*messageHeader,error){
	var command [commandSize]byte
	hdr := messageHeader{}
	err := readElements(r,&hdr.magic,&command,&hdr.length,&hdr.checksum)
	if err != nil {
		return nil,err
	}
	hdr.command = string(bytes.TrimRight(command[:],string(0)))
	if hdr.length > maxMessagePayload {
		str := "readMessageHeader: message payload is too large - " +
			"Header indicates %d bytes, but max message payload is %d bytes."
		return nil,fmt.Printf(str,hdr.length,maxMessagePayload)
	}
	return &hdr,nil
}

























































