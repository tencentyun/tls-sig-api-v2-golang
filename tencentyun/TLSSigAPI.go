package tencentyun

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strconv"
	"time"
)

/**
 *【功能说明】用于签发 TRTC 和 IM 服务中必须要使用的 UserSig 鉴权票据
 *
 *【参数说明】
 * sdkappid - 应用id
 * key - 计算 usersig 用的加密密钥,控制台可获取
 * userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
 * expire - UserSig 票据的过期时间，单位是秒，比如 86400 代表生成的 UserSig 票据在一天后就无法再使用了。
 */
func GenUserSig(sdkappid int, key string, userid string, expire int) (string, error) {
	return genSig(sdkappid, key, userid, expire, nil)
}

func GenUserSigWithBuf(sdkappid int, key string, userid string, expire int, buf []byte) (string, error) {
	return genSig(sdkappid, key, userid, expire, buf)
}

/**
 *【功能说明】
 * 用于签发 TRTC 进房参数中可选的 PrivateMapKey 权限票据。
 * PrivateMapKey 需要跟 UserSig 一起使用，但 PrivateMapKey 比 UserSig 有更强的权限控制能力：
 *  - UserSig 只能控制某个 UserID 有无使用 TRTC 服务的权限，只要 UserSig 正确，其对应的 UserID 可以进出任意房间。
 *  - PrivateMapKey 则是将 UserID 的权限控制的更加严格，包括能不能进入某个房间，能不能在该房间里上行音视频等等。
 * 如果要开启 PrivateMapKey 严格权限位校验，需要在【实时音视频控制台】=>【应用管理】=>【应用信息】中打开“启动权限密钥”开关。
 *
 *【参数说明】
 * sdkappid - 应用id。
 * key - 计算 usersig 用的加密密钥,控制台可获取。
 * userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
 * expire - PrivateMapKey 票据的过期时间，单位是秒，比如 86400 生成的 PrivateMapKey 票据在一天后就无法再使用了。
 * roomid - 房间号，用于指定该 userid 可以进入的房间号
 * privilegeMap - 权限位，使用了一个字节中的 8 个比特位，分别代表八个具体的功能权限开关：
 *  - 第 1 位：0000 0001 = 1，创建房间的权限
 *  - 第 2 位：0000 0010 = 2，加入房间的权限
 *  - 第 3 位：0000 0100 = 4，发送语音的权限
 *  - 第 4 位：0000 1000 = 8，接收语音的权限
 *  - 第 5 位：0001 0000 = 16，发送视频的权限
 *  - 第 6 位：0010 0000 = 32，接收视频的权限
 *  - 第 7 位：0100 0000 = 64，发送辅路（也就是屏幕分享）视频的权限
 *  - 第 8 位：1000 0000 = 200，接收辅路（也就是屏幕分享）视频的权限
 *  - privilegeMap == 1111 1111 == 255 代表该 userid 在该 roomid 房间内的所有功能权限。
 *  - privilegeMap == 0010 1010 == 42  代表该 userid 拥有加入房间和接收音视频数据的权限，但不具备其他权限。
 */
func GenPrivateMapKey(sdkappid int, key string, userid string, expire int, roomid uint32, privilegeMap uint32) (string, error) {
	var userbuf []byte = genUserBuf(userid, sdkappid, roomid, expire, privilegeMap, 0, "")
	return genSig(sdkappid, key, userid, expire, userbuf)
}

/**
 *【功能说明】
 * 用于签发 TRTC 进房参数中可选的 PrivateMapKey 权限票据。
 * PrivateMapKey 需要跟 UserSig 一起使用，但 PrivateMapKey 比 UserSig 有更强的权限控制能力：
 *  - UserSig 只能控制某个 UserID 有无使用 TRTC 服务的权限，只要 UserSig 正确，其对应的 UserID 可以进出任意房间。
 *  - PrivateMapKey 则是将 UserID 的权限控制的更加严格，包括能不能进入某个房间，能不能在该房间里上行音视频等等。
 * 如果要开启 PrivateMapKey 严格权限位校验，需要在【实时音视频控制台】=>【应用管理】=>【应用信息】中打开“启动权限密钥”开关。
 *
 *【参数说明】
 * sdkappid - 应用id。
 * key - 计算 usersig 用的加密密钥,控制台可获取。
 * userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
 * expire - PrivateMapKey 票据的过期时间，单位是秒，比如 86400 生成的 PrivateMapKey 票据在一天后就无法再使用了。
 * roomStr - 字符串房间号，用于指定该 userid 可以进入的房间号
 * privilegeMap - 权限位，使用了一个字节中的 8 个比特位，分别代表八个具体的功能权限开关：
 *  - 第 1 位：0000 0001 = 1，创建房间的权限
 *  - 第 2 位：0000 0010 = 2，加入房间的权限
 *  - 第 3 位：0000 0100 = 4，发送语音的权限
 *  - 第 4 位：0000 1000 = 8，接收语音的权限
 *  - 第 5 位：0001 0000 = 16，发送视频的权限
 *  - 第 6 位：0010 0000 = 32，接收视频的权限
 *  - 第 7 位：0100 0000 = 64，发送辅路（也就是屏幕分享）视频的权限
 *  - 第 8 位：1000 0000 = 200，接收辅路（也就是屏幕分享）视频的权限
 *  - privilegeMap == 1111 1111 == 255 代表该 userid 在该 roomid 房间内的所有功能权限。
 *  - privilegeMap == 0010 1010 == 42  代表该 userid 拥有加入房间和接收音视频数据的权限，但不具备其他权限。
 */
func GenPrivateMapKeyWithStringRoomID(sdkappid int, key string, userid string, expire int, roomStr string, privilegeMap uint32) (string, error) {
	var userbuf []byte = genUserBuf(userid, sdkappid, 0, expire, privilegeMap, 0, roomStr)
	return genSig(sdkappid, key, userid, expire, userbuf)
}

func genUserBuf(account string, dwSdkappid int, dwAuthID uint32,
	dwExpTime int, dwPrivilegeMap uint32, dwAccountType uint32, roomStr string) []byte {

	offset := 0
	length := 1 + 2 + len(account) + 20 + len(roomStr)
	if len(roomStr) > 0 {
		length = length + 2
	}

	userBuf := make([]byte, length)

	//ver
	if len(roomStr) > 0 {
		userBuf[offset] = 1
	} else {
		userBuf[offset] = 0
	}

	offset++
	userBuf[offset] = (byte)((len(account) & 0xFF00) >> 8)
	offset++
	userBuf[offset] = (byte)(len(account) & 0x00FF)
	offset++

	for ; offset < len(account)+3; offset++ {
		userBuf[offset] = account[offset-3]
	}

	//dwSdkAppid
	userBuf[offset] = (byte)((dwSdkappid & 0xFF000000) >> 24)
	offset++
	userBuf[offset] = (byte)((dwSdkappid & 0x00FF0000) >> 16)
	offset++
	userBuf[offset] = (byte)((dwSdkappid & 0x0000FF00) >> 8)
	offset++
	userBuf[offset] = (byte)(dwSdkappid & 0x000000FF)
	offset++

	//dwAuthId
	userBuf[offset] = (byte)((dwAuthID & 0xFF000000) >> 24)
	offset++
	userBuf[offset] = (byte)((dwAuthID & 0x00FF0000) >> 16)
	offset++
	userBuf[offset] = (byte)((dwAuthID & 0x0000FF00) >> 8)
	offset++
	userBuf[offset] = (byte)(dwAuthID & 0x000000FF)
	offset++

	//dwExpTime now+300;
	currTime := time.Now().Unix()
	var expire = currTime + int64(dwExpTime)
	userBuf[offset] = (byte)((expire & 0xFF000000) >> 24)
	offset++
	userBuf[offset] = (byte)((expire & 0x00FF0000) >> 16)
	offset++
	userBuf[offset] = (byte)((expire & 0x0000FF00) >> 8)
	offset++
	userBuf[offset] = (byte)(expire & 0x000000FF)
	offset++

	//dwPrivilegeMap
	userBuf[offset] = (byte)((dwPrivilegeMap & 0xFF000000) >> 24)
	offset++
	userBuf[offset] = (byte)((dwPrivilegeMap & 0x00FF0000) >> 16)
	offset++
	userBuf[offset] = (byte)((dwPrivilegeMap & 0x0000FF00) >> 8)
	offset++
	userBuf[offset] = (byte)(dwPrivilegeMap & 0x000000FF)
	offset++

	//dwAccountType
	userBuf[offset] = (byte)((dwAccountType & 0xFF000000) >> 24)
	offset++
	userBuf[offset] = (byte)((dwAccountType & 0x00FF0000) >> 16)
	offset++
	userBuf[offset] = (byte)((dwAccountType & 0x0000FF00) >> 8)
	offset++
	userBuf[offset] = (byte)(dwAccountType & 0x000000FF)
	offset++

	if len(roomStr) > 0 {
		userBuf[offset] = (byte)((len(roomStr) & 0xFF00) >> 8)
		offset++
		userBuf[offset] = (byte)(len(roomStr) & 0x00FF)
		offset++

		for ; offset < length; offset++ {
			userBuf[offset] = roomStr[offset-(length-len(roomStr))]
		}
	}

	return userBuf
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
	sigDoc := make(map[string]interface{})
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
	if _, err = w.Write(data); err != nil {
		return "", err
	}
	if err = w.Close(); err != nil {
		return "", err
	}
	return base64urlEncode(b.Bytes()), nil
}

// VerifyUserSig 检验UserSig在now时间点时是否有效
func VerifyUserSig(sdkappid uint64, key string, userid string, usersig string, now time.Time) error {
	sig, err := newUserSig(usersig)
	if err != nil {
		return err
	}
	return sig.verify(sdkappid, key, userid, now, nil)
}

// VerifyUserSigWithBuf 检验带UserBuf的UserSig在now时间点是否有效
func VerifyUserSigWithBuf(sdkappid uint64, key string, userid string, usersig string, now time.Time, userbuf []byte) error {
	sig, err := newUserSig(usersig)
	if err != nil {
		return err
	}
	return sig.verify(sdkappid, key, userid, now, userbuf)
}

type userSig struct {
	Version    string `json:"TLS.ver,omitempty"`
	Identifier string `json:"TLS.identifier,omitempty"`
	SdkAppID   uint64 `json:"TLS.sdkappid,omitempty"`
	Expire     int64  `json:"TLS.expire,omitempty"`
	Time       int64  `json:"TLS.time,omitempty"`
	UserBuf    []byte `json:"TLS.userbuf,omitempty"`
	Sig        string `json:"TLS.sig,omitempty"`
}

func newUserSig(usersig string) (userSig, error) {
	b, err := base64urlDecode(usersig)
	if err != nil {
		return userSig{}, err
	}
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return userSig{}, err
	}
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return userSig{}, err
	}
	if err = r.Close(); err != nil {
		return userSig{}, err
	}
	var sig userSig
	if err = json.Unmarshal(data, &sig); err != nil {
		return userSig{}, nil
	}
	return sig, nil
}

func (u userSig) verify(sdkappid uint64, key string, userid string, now time.Time, userbuf []byte) error {
	if sdkappid != u.SdkAppID {
		return ErrSdkAppIDNotMatch
	}
	if userid != u.Identifier {
		return ErrIdentifierNotMatch
	}
	if now.Unix() > u.Time+u.Expire {
		return ErrExpired
	}
	if userbuf != nil {
		if u.UserBuf == nil {
			return ErrUserBufTypeNotMatch
		}
		if !bytes.Equal(userbuf, u.UserBuf) {
			return ErrUserBufNotMatch
		}
	} else if u.UserBuf != nil {
		return ErrUserBufTypeNotMatch
	}
	if u.sign(key) != u.Sig {
		return ErrSigNotMatch
	}
	return nil
}

func (u userSig) sign(key string) string {
	var sb bytes.Buffer
	sb.WriteString("TLS.identifier:")
	sb.WriteString(u.Identifier)
	sb.WriteString("\n")
	sb.WriteString("TLS.sdkappid:")
	sb.WriteString(strconv.FormatUint(u.SdkAppID, 10))
	sb.WriteString("\n")
	sb.WriteString("TLS.time:")
	sb.WriteString(strconv.FormatInt(u.Time, 10))
	sb.WriteString("\n")
	sb.WriteString("TLS.expire:")
	sb.WriteString(strconv.FormatInt(u.Expire, 10))
	sb.WriteString("\n")
	if u.UserBuf != nil {
		sb.WriteString("TLS.userbuf:")
		sb.WriteString(base64.StdEncoding.EncodeToString(u.UserBuf))
		sb.WriteString("\n")
	}

	h := hmac.New(sha256.New, []byte(key))
	h.Write(sb.Bytes())
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// 错误类型
var (
	ErrSdkAppIDNotMatch    = errors.New("sdk appid not match")
	ErrIdentifierNotMatch  = errors.New("identifier not match")
	ErrExpired             = errors.New("expired")
	ErrUserBufTypeNotMatch = errors.New("userbuf type not match")
	ErrUserBufNotMatch     = errors.New("userbuf not match")
	ErrSigNotMatch         = errors.New("sig not match")
)
