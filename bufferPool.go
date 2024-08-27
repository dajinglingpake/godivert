package godivert

import "sync"

// 创建一个全局的缓冲池
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, PacketBufferSize)
	},
}

func GetBuffer() []byte {
	return bufferPool.Get().([]byte)
}

func ReturnBuffer(buffer []byte, length int) {
	if len(buffer) == PacketBufferSize {
		// 清理缓冲区内容
		for i := 0; i < length; i++ {
			buffer[i] = 0
		}
		bufferPool.Put(buffer)
	}
}
