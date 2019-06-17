package tencentyun

import (
	"encoding/base64"
	"strings"
)

func base64urlEncode(data []byte) string {
	str := base64.StdEncoding.EncodeToString(data)
	str = strings.Replace(str, "+", "*", -1)
	str = strings.Replace(str, "/", "-", -1)
	str = strings.Replace(str, "=", "_", -1)
	return str
}

func base64urlDecode(str string) ([]byte, error) {
	str = strings.Replace(str, "_", "=", -1)
	str = strings.Replace(str, "-", "/", -1)
	str = strings.Replace(str, "*", "+", -1)
	return base64.StdEncoding.DecodeString(str)
}
