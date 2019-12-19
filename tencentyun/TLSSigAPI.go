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
/**用于生成实时音视频(TRTC)业务进房权限加密串,具体用途用法参考TRTC文档：https://cloud.tencent.com/document/product/647/32240 
 * TRTC业务进房权限加密串需使用用户定义的userbuf
 * @brief 生成 userbuf
 * @param account 用户名
 * @param dwSdkappid sdkappid
 * @param dwAuthID  数字房间号
 * @param dwExpTime 过期时间：该权限加密串的过期时间，建议300秒.当前时间 + 有效期（单位：秒）
 * @param dwPrivilegeMap 用户权限，255表示所有权限
 * @param dwAccountType 用户类型,默认为0
 * @return byte[] userbuf
 */
func genUserBuf(account string, dwSdkappid int,dwAuthID uint32,
	dwExpTime int,dwPrivilegeMap uint32,dwAccountType uint32) []byte{

    offset := 0;
    length := 1+2+len(account)+20;
	userBuf := make([]byte,length);
    
    userBuf[offset]= 0;
    offset++;
    userBuf[offset] = (byte)((len(account) & 0xFF00) >> 8);
    offset++;
    userBuf[offset] =  (byte)(len(account) & 0x00FF);
    offset++;
        
    for ; offset < len(account) + 3; offset++{
        userBuf[offset] = account[offset-3];
    }
    
    //dwSdkAppid
    userBuf[offset] =  (byte)((dwSdkappid & 0xFF000000) >> 24);
    offset++;
    userBuf[offset] =  (byte)((dwSdkappid & 0x00FF0000) >> 16);
    offset++;
    userBuf[offset] =  (byte)((dwSdkappid & 0x0000FF00) >> 8);
    offset++;
    userBuf[offset] =  (byte)(dwSdkappid & 0x000000FF);
    offset++;
    
    //dwAuthId
    userBuf[offset] =  (byte)((dwAuthID & 0xFF000000) >> 24);
    offset++;
    userBuf[offset] =  (byte)((dwAuthID & 0x00FF0000) >> 16);
    offset++;
    userBuf[offset] =  (byte)((dwAuthID & 0x0000FF00) >> 8);
    offset++;
    userBuf[offset] =  (byte)(dwAuthID & 0x000000FF);
    offset++;
        
    //dwExpTime now+300;
    currTime := time.Now().Unix();
    var expire = currTime + int64(dwExpTime);
    userBuf[offset] =  (byte)((expire & 0xFF000000) >> 24);
    offset++;
    userBuf[offset] =  (byte)((expire & 0x00FF0000) >> 16);
    offset++;
    userBuf[offset] =  (byte)((expire & 0x0000FF00) >> 8);
    offset++;
    userBuf[offset] =  (byte)(expire & 0x000000FF);
    offset++;

    //dwPrivilegeMap     
    userBuf[offset] =  (byte)((dwPrivilegeMap & 0xFF000000) >> 24);
    offset++;
    userBuf[offset] =  (byte)((dwPrivilegeMap & 0x00FF0000) >> 16);
    offset++;
    userBuf[offset] =  (byte)((dwPrivilegeMap & 0x0000FF00) >> 8);
    offset++;
    userBuf[offset] =  (byte)(dwPrivilegeMap & 0x000000FF);
    offset++;
        
    //dwAccountType
    userBuf[offset] =  (byte)((dwAccountType & 0xFF000000) >> 24);
    offset++;
    userBuf[offset] =  (byte)((dwAccountType & 0x00FF0000) >> 16);
    offset++;
    userBuf[offset] =  (byte)((dwAccountType & 0x0000FF00) >> 8);
    offset++;
    userBuf[offset] =  (byte)(dwAccountType & 0x000000FF);
    offset++;  
	return userBuf;
}
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
/**用于生成实时音视频(TRTC)业务进房权限加密串,具体用途用法参考TRTC文档：https://cloud.tencent.com/document/product/647/32240 
 * @brief 生成带userbuf的sig
 * @param identifier 用户名
 * @param sdkappid sdkappid
 * @param roomnum  数字房间号
 * @param expire 过期时间：该权限加密串的过期时间，建议300秒.
 * @param privilege 用户权限，255表示所有权限
 * @return byte[] sig
 */
func GenSigWithUserBuf(sdkappid int, key string, identifier string, expire int, roomnum uint32,privilege uint32) (string, error) {
    var userbuf []byte = genUserBuf(identifier,sdkappid,roomnum,expire,privilege,0);
    return genSig(sdkappid, key, identifier, expire, userbuf)
}

