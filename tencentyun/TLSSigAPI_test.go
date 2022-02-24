package tencentyun

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenAndVerify(t *testing.T) {
	// 生成签名
	now := time.Now()
	sig, err := GenUserSig(1, "2", "3", 4)
	require.NoError(t, err)
	bufSig, err := GenUserSigWithBuf(1, "2", "3", 4, []byte{5})
	require.NoError(t, err)

	// 验证签名
	assert.NoError(t, VerifyUserSig(1, "2", "3", sig, now))
	assert.Equal(t, ErrExpired, VerifyUserSig(1, "2", "3", sig, now.Add(time.Hour)))
	assert.Equal(t, ErrSdkAppIDNotMatch, VerifyUserSig(2, "2", "3", sig, now))
	assert.Equal(t, ErrIdentifierNotMatch, VerifyUserSig(1, "2", "4", sig, now))
	assert.Equal(t, ErrSigNotMatch, VerifyUserSig(1, "3", "3", sig, now))
	assert.Equal(t, ErrUserBufTypeNotMatch, VerifyUserSig(1, "3", "3", bufSig, now))

	assert.NoError(t, VerifyUserSigWithBuf(1, "2", "3", bufSig, now, []byte{5}))
	assert.Equal(t, ErrExpired, VerifyUserSigWithBuf(1, "2", "3", bufSig, now.Add(time.Hour), []byte{5}))
	assert.Equal(t, ErrSdkAppIDNotMatch, VerifyUserSigWithBuf(2, "2", "3", bufSig, now, []byte{5}))
	assert.Equal(t, ErrIdentifierNotMatch, VerifyUserSigWithBuf(1, "2", "4", bufSig, now, []byte{5}))
	assert.Equal(t, ErrSigNotMatch, VerifyUserSigWithBuf(1, "3", "3", bufSig, now, []byte{5}))
	assert.Equal(t, ErrUserBufTypeNotMatch, VerifyUserSigWithBuf(1, "3", "3", bufSig, now, nil))
	assert.Equal(t, ErrUserBufNotMatch, VerifyUserSigWithBuf(1, "3", "3", bufSig, now, []byte{6}))
}
