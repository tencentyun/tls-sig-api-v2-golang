## 说明
此项目为 tls-sig-api-v2 （对称密钥版本）golang 实现版本，请注意，之前版本的非对称密钥无法使用此版 api，如需使用请查看[这里](https://github.com/tencentyun/tls-sig-api-golang)。

## 使用
``` go
import (
	"github.com/tencentyun/tls-sig-api-v2-golang/tencentyun"
	"fmt"
)

const (
	sdkappid = 1400000000
	key = "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e"
)

func main()  {
	sig, err := tencentyun.GenSig(sdkappid, key, "xiaojun", 86400*180)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(sig)
	}
}
```
