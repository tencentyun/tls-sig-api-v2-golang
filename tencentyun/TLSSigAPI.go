package tencentyun

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"
)

func hmacsha256(sdkappid int, key string, identifier string, currTime int64, expire int, base64UserBuf *string) string {
	var contentToBeSigned string
	contentToBeSigned = "TLS.identifier:" + identifier + "\n"
	contentToBeSigned += "TLS.sdkappid:" + strconv.Itoa(sdkappid) + "\n"
	contentToBeSigned += "TLS.time:" + strconv.FormatInt(currTime, 10) + "\n"
	contentToBeSigned += "TLS.expire:" + strconv.Itoa(expire) + "\n"
    if nil != base64UserBuf {
        contentToBeSigned += "TLS.userbuf:" + *base64UserBuf + "\n"
    }

	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(contentToBeSigned))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func genSig(sdkappid int, key string, identifier string, expire int, userbuf []byte) (string, error) {
	currTime := time.Now().Unix()
	var sigDoc map[string]interface{}
	sigDoc = make(map[string]interface{})
	sigDoc["TLS.ver"] = "2.0"
	sigDoc["TLS.identifier"] = identifier
	sigDoc["TLS.sdkappid"] = sdkappid
	sigDoc["TLS.expire"] = expire
	sigDoc["TLS.time"] = currTime
    var base64UserBuf string
    if nil != userbuf {
        base64UserBuf = base64.StdEncoding.EncodeToString(userbuf)
        sigDoc["TLS.userbuf"] = base64UserBuf
        sigDoc["TLS.sig"] = hmacsha256(sdkappid, key, identifier, currTime, expire, &base64UserBuf)
    } else {
        sigDoc["TLS.sig"] = hmacsha256(sdkappid, key, identifier, currTime, expire, nil)
    }

	data, err := json.Marshal(sigDoc)
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(data)
	w.Close()
	return base64urlEncode(b.Bytes()), nil
}

func GenSig(sdkappid int, key string, identifier string, expire int) (string, error) {
    return genSig(sdkappid, key, identifier, expire, nil)
}

func GenSigWithUserBuf(sdkappid int, key string, identifier string, expire int, userbuf []byte) (string, error) {
    return genSig(sdkappid, key, identifier, expire, userbuf)
}

