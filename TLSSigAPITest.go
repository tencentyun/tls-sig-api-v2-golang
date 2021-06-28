package main

import (
	"fmt"
	"github.com/tencentyun/tls-sig-api-v2-golang/tencentyun"
)

const (
	sdkappid = 1400000000
	key      = "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e"
)

func main() {
	sig, err := tencentyun.GenUserSig(sdkappid, key, "xiaojun", 86400*180)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(sig)
	}
	sig, err = tencentyun.GenPrivateMapKey(sdkappid, key, "xiaojun", 86400*180, 10000, 255)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(sig)
	}
	sig, err = tencentyun.GenPrivateMapKeyWithStringRoomID(sdkappid, key, "xiaojun", 86400*180, "1000000040", 255)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(sig)
	}
	sig, err = tencentyun.GenUserSigWithBuf(sdkappid, key, "xiaojun", 86400*180, []byte("abc"))
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(sig)
	}
}
