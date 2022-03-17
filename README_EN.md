## Note
This project is the go implementation of tls-sig-api-v2. Previous asymmetric keys cannot use APIs of this version. To enable them to use APIs of this version,[see here](https://github.com/tencentyun/tls-sig-api-golang).

## use
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
