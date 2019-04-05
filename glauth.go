package glauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// CreateQRCodeDefault - формируем код с настройками по умолчанию
func CreateQRCodeDefault(account, issuer string, key []byte) (code barcode.Barcode, err error) {
	code, err = CreateQRCode(account, issuer, "totp", key)
	if err != nil {
		log.Println("[error]", err)
		return
	}

	code, err = barcode.Scale(code, 200, 200)
	if err != nil {
		log.Println("[error]", err)
		return
	}

	return
}

// CreateQRCode - формируем qr код
// account - Аккаунт пользователя
// issuer - Название организации выдающей токен
// t - Тип токена, totp - по времени, hotp - по счетчику
// key - Ключ
func CreateQRCode(account, issuer, t string, key []byte) (code barcode.Barcode, err error) {
	secret := base32.StdEncoding.EncodeToString(key)
	if err != nil {
		log.Println("[error]", err)
		return
	}

	URL, err := url.Parse("otpauth://" + t)
	if err != nil {
		log.Println("[error]", err)
		return
	}

	URL.Path += "/" + url.PathEscape(issuer) + ":" + url.PathEscape(account)

	params := url.Values{}
	params.Add("secret", secret)
	params.Add("issuer", issuer)

	URL.RawQuery = params.Encode()
	code, err = qr.Encode(URL.String(), qr.H, qr.Auto)
	if err != nil {
		log.Println("[error]", err)
		return
	}

	return
}

// GetTOTPToken - получение токена по времени
func GetTOTPToken(key []byte) (code string, err error) {

	codeInt, err := GetTOTPTokenInt(key)
	if err != nil {
		log.Println("[error]", err)
		return
	}

	code = formatCode(codeInt)
	return
}

// GetTOTPTokenInt - получение токена по времени
func GetTOTPTokenInt(key []byte) (int, error) {
	interval := time.Now().Unix() / 30

	code, err := computeCode(key, interval)
	return int(code), err
}

// GetHOTPToken - получение токена по времени
func GetHOTPToken(key []byte, value int64) (code string, err error) {

	codeInt, err := GetHOTPTokenInt(key, value)
	if err != nil {
		log.Println("[error]", err)
		return
	}

	code = formatCode(codeInt)
	return
}

// GetHOTPTokenInt - получение токена по времени
func GetHOTPTokenInt(key []byte, value int64) (int, error) {
	code, err := computeCode(key, value)
	return int(code), err
}

// computeCode - считаем код
func computeCode(key []byte, value int64) (code uint32, err error) {

	hash := hmac.New(sha1.New, key)
	err = binary.Write(hash, binary.BigEndian, value)
	if err != nil {
		log.Println("[error]", err)
		return
	}

	h := hash.Sum(nil)
	offset := h[19] & 0x0f

	truncated := binary.BigEndian.Uint32(h[offset : offset+4])
	truncated &= 0x7fffffff

	code = truncated % 1000000

	return
}

func formatCode(codeInt int) string {
	code := strconv.FormatUint(uint64(codeInt), 10)
	if len(code) == 6 {
		return code
	}
	return strings.Repeat("0", 6-len(code)) + code
}
