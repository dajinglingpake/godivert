package main

import (
	godivert "examples"
	"fmt"
	"log"
	"os"
)

// 自动切换工作目录
func init() {
	// 程序所在目录
	var execDir = "C:\\Users\\dajinglingpake\\GolandProjects\\godivert\\examples"
	pwd, _ := os.Getwd()
	fmt.Println("开始工作目录", pwd)
	if pwd == execDir {
		fmt.Println("不需要切换工作目录")
		return
	}
	fmt.Println("切换工作目录到", execDir)
	if err := os.Chdir(execDir); err != nil {
		log.Fatal(err)
	}
	pwd, _ = os.Getwd()
	fmt.Println("切换后工作目录:", pwd)
}

func main() {
	godivert.LoadDLL("./WinDivert-2.2.2-A/x64/WinDivert.dll", "./WinDivert-2.2.2-A/x86/WinDivert.dll")

	winDivert, err := godivert.NewWinDivertHandle("true")
	if err != nil {
		panic(err)
	}
	defer winDivert.Close()

	packet, err := winDivert.Recv()
	if err != nil {
		panic(err)
	}

	fmt.Println(packet)

	packet.Send(winDivert)
}
