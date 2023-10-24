package awsapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	method_get  = "GET"
	method_post = "POST"
)

type Awsapi struct {
	accesskey       string
	secretkey       string
	method          string
	url             string
	content         string
	cloud           string
	region          string
	service         string
	requestdate     time.Time
	apiversion      int
	credentialScope string
	signedHeaders   string
	headers         map[string]string
	body            []byte
}

func New(accesskey string, secretkey string) *Awsapi {
	api := &Awsapi{accesskey: accesskey, secretkey: secretkey}
	api.cloud = "aws"
	api.region = "us-east-1"
	api.apiversion = 4
	api.headers = make(map[string]string)
	api.requestdate = time.Now()
	//api.requestdate = time.Unix(int64(1687336264), 0)
	return api
}

func (api *Awsapi) SetApiVersion(version int) {
	api.apiversion = version
}

func (api *Awsapi) SetCloud(cloud string) {
	api.cloud = cloud
}

func (api *Awsapi) SetRegion(region string) {
	api.region = region
}

func (api *Awsapi) SetService(service string) {
	api.service = service
}

func (api *Awsapi) SetBody(content string) {
	api.content = content
}

func (api *Awsapi) GetBody() []byte {
	return api.body
}

func (api *Awsapi) Call(method string, url string) (int, error) {
	api.url = url
	api.method = method

	api.setAuthHeader()

	req, _ := http.NewRequest(api.method, api.url, bytes.NewBuffer([]byte(api.content)))
	for k, v := range api.headers {
		req.Header.Add(k, v)
	}
	if api.method == method_post {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	var client *http.Client = &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}

	defer res.Body.Close()
	api.body, _ = ioutil.ReadAll(res.Body)

	return res.StatusCode, nil
}

func (api *Awsapi) setAuthHeader() {
	switch api.apiversion {
	case 2:
		api.setAuthHeaderV2()
	case 3:
		api.setAuthHeaderV3()
	case 4:
		api.setAuthHeaderV4()
	}
}

func (api *Awsapi) setAuthHeaderV2() {
	base, _ := url.Parse(api.url)
	var param string
	switch api.method {
	case method_get:
		param = api.createCanonicalQueryString(base.RawQuery)
	case method_post:
		param = api.content
	}
	qs := fmt.Sprintf("AccessKeyId=%s&Timestamp=%s&SignatureVersion=2&SignatureMethod=HmacSHA256",
		api.accesskey,
		url.QueryEscape(api.requestdate.UTC().Format("2006-01-02T15:04:05Z")),
	)
	bss := []string{
		api.method,
		base.Host,
		base.Path,
		api.createCanonicalQueryString(param + "&" + qs),
	}
	ss := strings.Join(bss, "\n")

	mSignature := hmac.New(sha256.New, []byte(api.secretkey))
	mSignature.Write([]byte(ss))
	signature := base64.StdEncoding.EncodeToString(mSignature.Sum(nil))

	switch api.method {
	case method_get:
		api.url += "&" + qs + "&Signature=" + url.QueryEscape(signature)
	case method_post:
		api.content += "&" + qs + "&Signature=" + url.PathEscape(signature)
	}
}

func (api *Awsapi) setAuthHeaderV3() {
	api.setDateHeader("Mon, 02 Jan 2006 15:04:05 GMT")
	api.setHostHeader()
	mSignature := hmac.New(sha256.New, []byte(api.secretkey))
	mSignature.Write([]byte(api.requestdate.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")))
	signature := base64.StdEncoding.EncodeToString(mSignature.Sum(nil))
	key := fmt.Sprintf("X-%s-Authorization", api.getAuthHeaderStr())
	auth := fmt.Sprintf("%s3-HTTPS %sAccessKeyId=%s,Algorithm=HmacSHA256,Signature=%s",
		strings.ToUpper(api.cloud),
		strings.ToUpper(api.cloud),
		api.accesskey,
		signature,
	)
	api.headers[key] = auth
}

func (api *Awsapi) getAuthHeaderStr() string {
	switch api.cloud {
	case "aws":
		return "Amzn"
	default:
		return strings.Title(api.cloud)
	}
}

func (api *Awsapi) setAuthHeaderV4() {
	api.setDateHeader("20060102T150405Z")
	api.setHostHeader()
	cr := api.createCanonicalRequest()
	ss := api.createStringToSign(cr)
	sg := api.calclulateSignature()
	f, _ := os.Create("foo.txt")
	fmt.Fprint(f, cr, ss)
	mSignature := hmac.New(sha256.New, []byte(sg))
	mSignature.Write([]byte(ss))
	signature := hex.EncodeToString(mSignature.Sum(nil))
	auth := fmt.Sprintf("%s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		strings.ToUpper(api.cloud),
		api.accesskey,
		api.credentialScope,
		api.signedHeaders,
		signature)
	api.headers["Authorization"] = auth
}

func (api *Awsapi) setDateHeader(format string) {
	key := fmt.Sprintf("X-%s-Date", api.getDateHeaderStr())
	api.headers[key] = api.requestdate.UTC().Format(format)
}

func (api *Awsapi) getDateHeaderStr() string {
	switch api.cloud {
	case "aws":
		return "Amz"
	default:
		return strings.Title(api.cloud)
	}
}

func (api *Awsapi) setHostHeader() {
	base, _ := url.Parse(api.url)
	api.headers["Host"] = base.Host
}

func (api *Awsapi) createCanonicalRequest() string {
	api.setCredentialScope()
	base, _ := url.Parse(api.url)
	cqs := api.createCanonicalQueryString(base.RawQuery)
	ch := api.createCanonicalHeaders()
	res := []string{
		api.method,
		base.Path,
		cqs,
		ch,
		api.signedHeaders,
		fmt.Sprintf("%x", sha256.Sum256([]byte(api.content))),
	}
	//fmt.Println(strings.Join(res, "\n"))
	return strings.Join(res, "\n")
}

func (api *Awsapi) setCredentialScope() {
	api.credentialScope = fmt.Sprintf("%s/%s/%s/%s4_request",
		api.requestdate.UTC().Format("20060102"),
		api.region,
		api.service,
		api.cloud)
	//fmt.Println(api.credentialScope)
}

func (api *Awsapi) createCanonicalQueryString(querystring string) string {
	query := strings.Split(querystring, "&")
	sort.Strings(query)
	return strings.Join(query, "&")
}

func (api *Awsapi) createCanonicalHeaders() string {
	var sh []string
	var res []string
	for k, v := range api.headers {
		sh = append(sh, strings.ToLower(k))
		vv := strings.TrimSpace(strings.Join(strings.Fields(v), " "))
		res = append(res, strings.ToLower(k)+":"+vv)
	}
	sort.Strings(sh)
	sort.Strings(res)
	api.signedHeaders = strings.Join(sh, ";")
	//fmt.Println(res)
	return strings.Join(res, "\n") + "\n"
}

func (api *Awsapi) createStringToSign(cr string) string {
	res := []string{
		fmt.Sprintf("%s4-HMAC-SHA256", strings.ToUpper(api.cloud)),
		api.requestdate.UTC().Format("20060102T150405Z"),
		api.credentialScope,
		fmt.Sprintf("%x", sha256.Sum256([]byte(cr))),
	}
	//fmt.Println(strings.Join(res, "\n"))
	return strings.Join(res, "\n")
}

func (api *Awsapi) calclulateSignature() string {
	kSecret := api.secretkey
	mDate := hmac.New(sha256.New, []byte(strings.ToUpper(api.cloud)+"4"+kSecret))
	mDate.Write([]byte(api.requestdate.UTC().Format("20060102")))
	kDate := mDate.Sum(nil)
	mRegion := hmac.New(sha256.New, kDate)
	mRegion.Write([]byte(api.region))
	kRegion := mRegion.Sum(nil)
	mService := hmac.New(sha256.New, kRegion)
	mService.Write([]byte(api.service))
	kService := mService.Sum(nil)
	mSigning := hmac.New(sha256.New, kService)
	mSigning.Write([]byte(strings.ToLower(api.cloud) + "4_request"))
	kSigning := mSigning.Sum(nil)
	/*
		fmt.Println(strings.ToUpper("aws") + "4" + kSecret, api.region, api.service, strings.ToLower("aws") + "4_request")
		fmt.Println(hex.EncodeToString(kDate))
		fmt.Println(hex.EncodeToString(kRegion))
		fmt.Println(hex.EncodeToString(kService))

		fmt.Println(hex.EncodeToString(kSigning))
	*/
	return string(kSigning)
}
