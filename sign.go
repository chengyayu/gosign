package gosign

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Generator struct {
	liveMinutes int    // 生命周期
	ak          string // 公钥
	sk          string // 私钥
	accessTs    string // 请求时刻时间戳
}

type OptionFn func(*Generator)

func LiveMinutes(live int) OptionFn {
	return func(g *Generator) {
		g.liveMinutes = live
	}
}

func NewGenerator(ak, sk, accessTs string, options ...OptionFn) *Generator {
	g := &Generator{
		liveMinutes: 2, // default live
		ak:          ak,
		sk:          sk,
		accessTs:    accessTs,
	}
	for _, fn := range options {
		fn(g)
	}
	return g
}

func (p *Generator) GenerateSign(r *http.Request) string {
	return upperMD5(p.strToSign(r))
}

func (p *Generator) strToSign(r *http.Request) string {
	var str string

	qParams := withHeaders(r, p.ak, p.accessTs)
	sortedKeys := sortKeys(qParams)

	for _, k := range sortedKeys {
		str += k + "=" + url.QueryEscape(qParams[k]) + "&"
	}

	if bParams := bodyParams(r); bParams != "" {
		str += bParams + "&"
	}

	return str + "secret=" + upperMD5(p.sk)
}

func (p *Generator) VerifySign(r *http.Request, clientSign string) bool {
	return p.GenerateSign(r) == clientSign
}

func (p *Generator) SignTimeout(accessTs string) bool {
	return int(timeSpanMinutes(accessTs)) > p.liveMinutes
}

// just support http.MethodGet and http.MethodPost
func queryParams(r *http.Request) map[string][]string {
	fns := map[string]func() url.Values{
		http.MethodGet: r.URL.Query,
		http.MethodPost: func() url.Values {
			_ = r.ParseForm()
			return r.Form
		},
	}
	return fns[r.Method]()
}

func withHeaders(r *http.Request, ak, accessTs string) map[string]string {
	result := map[string]string{
		"ak":       ak,
		"accessTs": accessTs,
	}
	for k, v := range queryParams(r) {
		if k == "" || v[0] == "" {
			continue
		}
		result[k] = v[0]
	}
	return result
}

// just support http.MethodPost
func bodyParams(r *http.Request) string {
	if r.Method != http.MethodPost {
		return ""
	}

	bodyBytes, _ := ioutil.ReadAll(r.Body)
	defer func() {
		// 新建缓冲区并替换原有Request.body
		r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	}()
	if len(bodyBytes) == 0 {
		return ""
	}
	return upperMD5(string(bodyBytes))
}

// sort keys by lexicographical order
func sortKeys(mp map[string]string) []string {
	var keys []string
	for k := range mp {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// upper the MD5(text)
func upperMD5(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	md5Str := hex.EncodeToString(hasher.Sum(nil))
	return strings.ToUpper(md5Str)
}

// 计算一个字符时间戳与当前时间的时间差（分钟）
func timeSpanMinutes(unix string) float64 {
	i, err := strconv.ParseInt(unix, 10, 64)
	if err != nil {
		i = time.Now().AddDate(0, 0, -7).Unix()
	}
	tm := time.Unix(i, 0)
	tmSpan := time.Now().Sub(tm)
	return tmSpan.Seconds() / 60.0
}
