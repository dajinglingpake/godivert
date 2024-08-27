package godivert

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	winDivertDLL *syscall.LazyDLL

	winDivertOpen                *syscall.LazyProc
	winDivertClose               *syscall.LazyProc
	winDivertRecv                *syscall.LazyProc
	winDivertSend                *syscall.LazyProc
	winDivertHelperCalcChecksums *syscall.LazyProc
	winDivertHelperEvalFilter    *syscall.LazyProc
	winDivertHelperCheckFilter   *syscall.LazyProc
)

func init() {
	LoadDLL("WinDivert.dll", "WinDivert.dll")
}

// Used to call WinDivert's functions
type WinDivertHandle struct {
	handle uintptr
	open   bool
}

// LoadDLL loads the WinDivert DLL depending the OS (x64 or x86) and the given DLL path.
// The path can be a relative path (from the .exe folder) or absolute path.
func LoadDLL(path64, path32 string) {
	var dllPath string

	if runtime.GOARCH == "amd64" {
		dllPath = path64
	} else {
		dllPath = path32
	}

	winDivertDLL = syscall.NewLazyDLL(dllPath)

	winDivertOpen = winDivertDLL.NewProc("WinDivertOpen")
	winDivertClose = winDivertDLL.NewProc("WinDivertClose")
	winDivertRecv = winDivertDLL.NewProc("WinDivertRecv")
	winDivertSend = winDivertDLL.NewProc("WinDivertSend")
	winDivertHelperCalcChecksums = winDivertDLL.NewProc("WinDivertHelperCalcChecksums")
	winDivertHelperEvalFilter = winDivertDLL.NewProc("WinDivertHelperEvalFilter")
	winDivertHelperCheckFilter = winDivertDLL.NewProc("WinDivertHelperCheckFilter")
}

// Create a new WinDivertHandle by calling WinDivertOpen and returns it
// The string parameter is the fiter that packets have to match
// https://reqrypt.org/windivert-doc.html#divert_open
func NewWinDivertHandle(filter string) (*WinDivertHandle, error) {
	return NewWinDivertHandleWithFlags(filter, 0)
}

// Create a new WinDivertHandle by calling WinDivertOpen and returns it
// The string parameter is the fiter that packets have to match
// and flags are the used flags used
// https://reqrypt.org/windivert-doc.html#divert_open
func NewWinDivertHandleWithFlags(filter string, flags uint8) (*WinDivertHandle, error) {
	//使用 syscall.BytePtrFromString 将 filter 字符串转换为一个 C 风格的字符串（以 null 结尾的字节数组），并返回其指针。
	filterBytePtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	//存储 WinDivert 设备句柄。
	handle, _, err := winDivertOpen.Call(uintptr(unsafe.Pointer(filterBytePtr)),
		uintptr(0),
		uintptr(0),
		uintptr(flags))
	//检查 handle 是否等于 syscall.InvalidHandle，表示打开设备失败。
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, err
	}
	//创建一个新的 WinDivertHandle 结构体实例，初始化其 handle 字段为刚刚获得的设备句柄，open 字段为 true。
	winDivertHandle := &WinDivertHandle{
		handle: handle,
		open:   true,
	}
	return winDivertHandle, nil
}

// Close the Handle
// See https://reqrypt.org/windivert-doc.html#divert_close
func (wd *WinDivertHandle) Close() error {
	_, _, err := winDivertClose.Call(wd.handle)
	wd.open = false
	return err
}

// Divert a packet from the Network Stack
// https://reqrypt.org/windivert-doc.html#divert_recv
// api要求要尽可能的快读取数据包，所以消费之前可以提前读取
func (wd *WinDivertHandle) Recv() (*Packet, error) {
	//如果 WinDivertHandle 对象的 open 属性为 false，则返回一个错误，表示句柄未打开，无法接收数据包。
	if !wd.open {
		return nil, errors.New("can't receive, the handle isn't open")
	}
	// 从缓冲池中获取一个字节数组 packetBuffer
	packetBuffer := GetBuffer()
	//定义了一个 packetLen 变量，用于存储接收到的数据包的长度。
	var packetLen uint
	//用于存储数据包的地址信息，类型为 WinDivertAddress。
	var addr WinDivertAddress
	//调用 winDivertRecv 函数来接收数据包。
	success, _, err := winDivertRecv.Call(
		wd.handle,
		uintptr(unsafe.Pointer(&packetBuffer[0])),
		uintptr(PacketBufferSize),
		uintptr(unsafe.Pointer(&packetLen)),
		uintptr(unsafe.Pointer(&addr)))
	//如果 success 为 0，表示接收失败，返回错误。
	if success == 0 {
		return nil, err
	}

	packet := &Packet{
		Raw:       packetBuffer[:packetLen], //截获的数据包的原始字节数组。
		Addr:      &addr,                    //数据包的地址信息。
		PacketLen: packetLen,                //数据包的长度。
		buffer:    packetBuffer,             // 保存原始缓冲区
	}

	return packet, nil

}

// Inject the packet on the Network Stack
// https://reqrypt.org/windivert-doc.html#divert_send
// winDivertSend 是 WinDivert 库中的一个函数，用于将数据包注入网络堆栈。
// 它的定义如下：
// BOOL WinDivertSend(
//
//	__in HANDLE handle,
//	__in const VOID *pPacket,
//	__in UINT packetLen,
//	__out_opt UINT *pSendLen,
//	__in const WINDIVERT_ADDRESS *pAddr
//
// );
//
// 参数说明：
// - handle: 一个有效的 WinDivert 句柄，由 WinDivertOpen() 创建。
// - pPacket: 包含要注入的数据包的缓冲区。
// - packetLen: pPacket 缓冲区的总长度。
// - pSendLen: 实际注入的字节数，可以为 NULL。
// - pAddr: 要注入的数据包的地址。
//
// 返回值：
// - 成功时返回 TRUE，失败时返回 FALSE。使用 GetLastError() 获取错误原因。
//
// 常见错误包括：
//   - ERROR_HOST_UNREACHABLE: 当注入的伪造数据包（pAddr->Impostor 设置为 1）且 ip.TTL 或 ipv6.HopLimit 字段变为零时发生。
//     这是为了防止由伪造数据包引起的无限循环。
//
// 备注：
// 该函数将数据包注入网络堆栈。注入的数据包可以是从 WinDivertRecv() 接收到的数据包、修改后的版本或全新的数据包。
// 只有 WINDIVERT_LAYER_NETWORK 和 WINDIVERT_LAYER_NETWORK_FORWARD 层支持数据包注入。
// 对于 WINDIVERT_LAYER_NETWORK 层，pAddr->Outbound 值决定数据包注入的方向。
// 对于伪造数据包，WinDivert 会在重新注入之前自动递减 ip.TTL 或 ipv6.HopLimit 字段。
// 注入的数据包必须具有正确的校验和，或者相应的 pAddr->*Checksum 标志未设置。
// 使用 WinDivertHelperCalcChecksums() 函数可以重新计算校验和。
func (wd *WinDivertHandle) Send(packet *Packet) (uint, error) {
	var sendLen uint

	if !wd.open {
		return 0, errors.New("can't Send, the handle isn't open")
	}

	// 调试输出
	//fmt.Printf("handle: %v\n", wd.handle)
	//fmt.Printf("packet.Raw: %v\n", packet.Raw)
	//fmt.Printf("packet.PacketLen: %v\n", packet.PacketLen)
	//fmt.Printf("sendLen: %v\n", sendLen)
	//fmt.Printf("packet.Addr: %v\n", packet.Addr)

	success, _, err := winDivertSend.Call(
		wd.handle, // handle: 一个有效的 WinDivert 句柄，由 WinDivertOpen() 创建
		uintptr(unsafe.Pointer(&(packet.Raw[0]))), // pPacket: 包含要注入的数据包的缓冲区首字节的内存地址，从该地址按长度往后读
		uintptr(packet.PacketLen),                 // packetLen: pPacket 缓冲区的总长度
		uintptr(unsafe.Pointer(&sendLen)),         // pSendLen: 实际注入的字节数，可以为 NULL
		uintptr(unsafe.Pointer(packet.Addr)))      // pAddr: 要注入的数据包的地址

	// 将缓冲区放回缓冲池
	ReturnBuffer(packet.getBuffer(), int(packet.PacketLen))

	if success == 0 {
		return 0, err
	}

	return sendLen, nil
}

// Calls WinDivertHelperCalcChecksum to calculate the packet's chacksum
// https://reqrypt.org/windivert-doc.html#divert_helper_calc_checksums
func (wd *WinDivertHandle) HelperCalcChecksum(packet *Packet) error {
	initialPacketLen := packet.PacketLen

	success, _, err := winDivertHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packet.Raw[0])), //将数据包的原始字节数组 Raw 的首地址转换为 uintptr 类型。unsafe.Pointer 用于将 Go 的指针类型转换为通用指针类型，然后再转换为 uintptr
		uintptr(packet.PacketLen),               //数据包的长度，直接转换为 uintptr 类型。
		uintptr(unsafe.Pointer(&packet.Addr)),   //数据包的地址信息的首地址，同样通过 unsafe.Pointer 转换为 uintptr。
		uintptr(0))
	//用于控制校验和计算的标志，这里传递 0 表示计算所有类型的校验和
	if initialPacketLen != packet.PacketLen {
		//fmt.Printf("After Call PacketLen: %d\n", packet.PacketLen)
		packet.PacketLen = initialPacketLen
	}

	if success == 0 {
		return err
	}

	return nil
}

// Take the given filter and check if it contains any error
// https://reqrypt.org/windivert-doc.html#divert_helper_check_filter
func HelperCheckFilter(filter string) (bool, int) {
	var errorPos uint

	filterBytePtr, _ := syscall.BytePtrFromString(filter)

	success, _, _ := winDivertHelperCheckFilter.Call(
		uintptr(unsafe.Pointer(filterBytePtr)),
		uintptr(0),
		uintptr(0), // Not implemented yet
		uintptr(unsafe.Pointer(&errorPos)))

	if success == 1 {
		return true, -1
	}
	return false, int(errorPos)
}

// Take a packet and compare it with the given filter
// Returns true if the packet matches the filter
// https://reqrypt.org/windivert-doc.html#divert_helper_eval_filter
func HelperEvalFilter(packet *Packet, filter string) (bool, error) {
	filterBytePtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return false, err
	}

	success, _, err := winDivertHelperEvalFilter.Call(
		uintptr(unsafe.Pointer(filterBytePtr)),
		uintptr(0),
		uintptr(unsafe.Pointer(&packet.Raw[0])),
		uintptr(packet.PacketLen),
		uintptr(unsafe.Pointer(&packet.Addr)))

	if success == 0 {
		return false, err
	}

	return true, nil
}

// A loop that capture packets by calling Recv and sends them on a channel as long as the handle is open
// If Recv() returns an error, the loop is stopped and the channel is closed
// 这个函数的主要功能是不断地捕获网络数据包并将其发送到一个通道中，直到发生错误或句柄关闭为止。它是一个典型的生产者-消费者模式的实现，recvLoop 方法作为生产者不断地捕获数据包并将其发送到通道，而消费者可以从通道中接收数据包并进行处理。
func (wd *WinDivertHandle) recvLoop(packetChan chan<- *Packet) {
	for wd.open {
		// 读取数据放到缓冲队列中，这样如果消费比较慢也能提前读取，避免包丢失
		packet, err := wd.Recv()
		if err != nil {
			//close(packetChan)
			fmt.Println("recvLoop Recv Error:", err)
			break
		}

		packetChan <- packet
	}
}

// Create a new channel that will be used to pass captured packets and returns it calls recvLoop to maintain a loop
func (wd *WinDivertHandle) Packets() (chan *Packet, error) {
	if !wd.open {
		return nil, errors.New("the handle isn't open")
	}
	packetChan := make(chan *Packet, PacketChanCapacity)
	// 异步把数据读到缓冲队列中
	go wd.recvLoop(packetChan)
	return packetChan, nil
}
