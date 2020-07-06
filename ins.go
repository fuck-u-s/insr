package main

import (
	"./gapi"
	"./hapi"
	"active_apple/ml/random"
	"bytes"
	"container/list"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	proxybin    = "insgost.exe"
	closeCmdFmt = "netstat -anto|grep LISTEN|grep %s|grep -v grep|head -n 1|awk '{printf $5}'"
	keycache    = make(map[string]*EncKey)
	keys        = list.New()
	hasClient   = false
	proxy_port  = 0
	proxyAddr   = "socks5://127.0.0.1:%s"
	saveLoglock sync.Mutex //互斥锁
	mailLock    sync.Mutex //互斥锁
	Max_count   int        = 20
)

func init() {
	flag.IntVar(&Max_count, "c", 20, "默认线程数")

	switch runtime.GOOS {
	case "darwin":
		{
			proxybin = "gost"
			break
		}
	case "windows":
		{
			proxybin = "insgost.exe"
			closeCmdFmt = "netstat -anto|grep LISTEN|grep %s|grep -v grep|head -n 1|gawk '{printf $5}'"
			break
		}
	case "linux":
		{
			proxybin = "gost"
			closeCmdFmt = "netstat -antp|grep LISTEN|grep %s|grep -v grep|head -n 1|awk '{print $7}'|awk -F'/' '{printf $1}'"
			break
		}
	}
}

func stringVal(val, key string) (string, bool) {
	keyLen := len(key)
	keyIndex := strings.Index(val, key)
	if keyIndex < 0 {
		return "", false
	}
	keyEndIndex := strings.Index(val[keyIndex+keyLen:len(val)], "\"")
	start := keyIndex + keyLen
	end := keyIndex + keyLen + keyEndIndex
	return val[start:end], true
}

type Account struct {
	Name      string
	Email     string
	Pwd       string
	Username  string
	Mid       string
	DeviceId  string
	Rur       string
	CsrfToken string
	Byear     string
	Bmonth    string
	Bday      string
}

type EncKey struct {
	Keyid   string
	Version string
	Key     string
	Pwd     string
	EncPwd  string
}

type FileHandler struct {
	Index []byte
}

type ProxyRun func(proxy string) bool

func FileResolver(path string, handler *FileHandler) bool {
	indexContent, err := ioutil.ReadFile(path)
	handler.Index = indexContent
	return err == nil
}

func onKey(w http.ResponseWriter, r *http.Request) {
	hasClient = true
	if keys.Len() > 0 {
		front := keys.Front()
		if front != nil {
			keys.Remove(front)
			valKey := front.Value.(string)
			if encKey, ok := keycache[valKey]; ok {
				w.Write([]byte(fmt.Sprintf(`{"a":"%s","b":"%s","c":"%s","d":"%s","e":"%s"}`, valKey, encKey.Keyid, encKey.Version, encKey.Key, encKey.Pwd)))
				return
			}
		}
	}
	w.Write([]byte(`{}`))
}

func onData(w http.ResponseWriter, r *http.Request) {
	enckey := r.PostFormValue("a")
	encpwd := r.PostFormValue("b")
	key := keycache[enckey]
	key.EncPwd = encpwd
	println("enckey\t", enckey)
	println("encpwd\t", encpwd)
	w.Write([]byte("ok"))
}

func main_ajax() {
	mux := http.NewServeMux()
	handler := FileHandler{}
	if FileResolver("index.html", &handler) {
		println("register index.html")
		mux.Handle("/", &handler)
	}

	jshandler := FileHandler{}
	if FileResolver("temp.js", &jshandler) {
		println("register temp.js")
		mux.Handle("/temp.js", &jshandler)
	}

	jqshandler := FileHandler{}
	if FileResolver("jquery.js", &jqshandler) {
		println("register jquery.js")
		mux.Handle("/jquery.js", &jqshandler)
	}

	mux.HandleFunc("/onkey", onKey)
	mux.HandleFunc("/data", onData)

	println("Starting v2 httpserver")
	//println(http.ListenAndServe(":1210", mux))
	println(http.ListenAndServeTLS(":443", "cert.pem", "key.pem", mux))
}

func (t *FileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write(t.Index)
}



func main111() {
	closeProByPort("10081")
	closeProByPort("10082")
}

func main_proxyvpn() {
	local_port := "10081"
	server_port := "4008"

	go func() { main_ajax() }()
	for !hasClient {
		println("wait encrypt client online......")
		time.Sleep(1 * time.Second)
	}

	hclient := &gapi.HClient{ProxyAddr: proxyAddr, LocalPort: local_port}
	client := gapi.Ctx{Isdebug: true}
	for i := 0; i < 10; i++ {
		changeYlIp(client, server_port)

		main_register(hclient)

		time.Sleep(5 * time.Second)
	}
}

func main_local() {
	go func() { main_ajax() }()
	for !hasClient {
		println("wait encrypt client online......")
		time.Sleep(1 * time.Second)
	}
	ctx := hapi.Ctx{Isdebug: false, Modem_host: "192.168.8.1", Username: "admin", Password: "bluehawk", Ppinfo: "", Version: "2020.0410.1750"}
	ctx.ChangeIp(func(ppinfo string, authinfo string, serial string, ischange bool) {
		main_register(nil)
	})
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU() * 3)

	go func() { main_ajax() }()
	for !hasClient {
		println("wait encrypt client online......")
		time.Sleep(1 * time.Second)
	}

	var wait sync.WaitGroup
	count := 0

	for count = 0; count < Max_count; count++ {
		localPort := 10081 + count

		localPortStr := fmt.Sprintf("%d", localPort)
		hclient := &gapi.HClient{ProxyAddr: proxyAddr, LocalPort: localPortStr}
		go func() {
			defer func() {
				recover()
				wait.Done()
			}()
			for {
				proxy_port = rand.Intn(49999-10000) + 10000
				proxyRunSmart(localPortStr, proxy_port, hclient, func(proxy string) bool {
					main_register(hclient)
					return true
				})
			}
		}()
	}

	wait.Add(count)
	wait.Wait()
}

func Get1(url string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	var req *http.Request
	req, _ = http.NewRequest(http.MethodGet, url, strings.NewReader(""))
	resp, err := client.Do(req)
	if err != nil {
		println(err)
		return ""
	}
	defer resp.Body.Close()
	var buffer [512]byte
	result := bytes.NewBuffer(nil)
	for {
		n, err := resp.Body.Read(buffer[0:])
		result.Write(buffer[0:n])
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return ""
		}
	}
	return result.String()
}

func _nextEmail(api gapi.Ctx) string {
	url := "http://linshiyouxiang.net/api/v1/mailbox/keepalive?force_change=1"
	content := api.Get(url)
	mark := `"mailbox":"`
	if strings.Contains(content, mark) {
		val, b := stringVal(content, mark)
		if b {
			return val
		}
	}
	return ""
}

func NextEmail(api gapi.Ctx) (string, string) {
	mailLock.Lock()
	defer mailLock.Unlock()

	emailSuffixs := []string{"linshiyouxiang.net", "meantinc.com", "classesmail.com", "powerencry.com", "groupbuff.com", "unicodeworld.com", "allemojikeyboard.com", "temporary-mail.net"}
	emailSuffix := random.ChoiceString(emailSuffixs)
	emailName := ""
	for i := 0; i < 10; i++ {
		emailName = _nextEmail(api)
		if emailName == "" {
			time.Sleep(1 * time.Second)
		} else {
			break
		}
	}
	return emailName, emailSuffix
}

func EmailCode(email string, api gapi.Ctx) (string, bool) {
	content := ""
	for i := 0; i < 30; i++ {
		//[{"mailbox":"zh00n1f3","id":"5efdbaf88eaad10708802ad3","from":"Instagram","to":["\u003czh00n1f3@linshiyouxiang.net\u003e"],"subject":"157964 is your Instagram code","date":"2020-07-02T18:46:16+08:00","size":6999,"seen":false}]
		url := fmt.Sprintf("http://www.linshiyouxiang.net/api/v1/mailbox/%s", email)
		//content = strings.TrimSpace(Get1(url))
		content = strings.TrimSpace(api.Get(url))
		if strings.Contains(content, `"subject":"`) {
			println("EmailCode\t", "|"+content+"|")
			val, b := stringVal(content, `"subject":"`)
			if b && len(val) > 0 {
				content = strings.Split(val, " ")[0]
				return content, true
			}
		}
		time.Sleep(3 * time.Second)
	}
	return content, false
}

func main_register(hclient *gapi.HClient) {
	account := Account{}
	useragent := gapi.RandUserAgentPc()
	client := gapi.Ctx{Isdebug: true, OnHttpClient: hclient}

	ip := ip138(client, "")
	println("current ip \t" + ip)
	hasInfo := false
	for i := 0; i < 5; i++ {
		if !rundomuser(client, &account) {
			println("fetch user info fail....")
			time.Sleep(2 * time.Second)
			continue
		}
		hasInfo = true
		break
	}
	if !hasInfo {
		return
	}

	emialPrefix, emailSuffix := NextEmail(client)
	if emialPrefix == "" {
		println("look up email fail!!")
		return
	}

	account.Email = fmt.Sprintf("%s@%s", emialPrefix, emailSuffix)
	account.Pwd = gapi.Random_pwd(12)

	var _headers map[string]string = make(map[string]string)
	var _cookies map[string]string = make(map[string]string)
	_cookies["ig_cb"] = "1"

	initHeaders := map[string]string{
		"User-Agent":       useragent,
		"Accept":           "*/*",
		"Accept-Language":  "en-US,en;q=0.5",
		"X-Instagram-AJAX": "fc31028544fb",
		"X-IG-App-ID":      "936619743392459",
		"X-IG-WWW-Claim":   "0",
		"X-Requested-With": "XMLHttpRequest",
		"Origin":           "https://www.instagram.com",
		"Referer":          "https://www.instagram.com/accounts/emailsignup/",
		"Connection":       "keep-alive",
		"Pragma":           "no-cache",
		"Cache-Control":    "no-cache",
	}
	for k, v := range initHeaders {
		println(k, v)
		_headers[k] = v
	}

	var secondHeader map[string]string = make(map[string]string)

	curl1 := "https://www.instagram.com/accounts/emailsignup"
	//curl := "https://www.instagram.com/accounts/emailsignup/?__a=1"
	curl := "https://www.instagram.com/data/shared_data/?__a=1"
	api := gapi.Ctx{Isdebug: true, Headers: &map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Accept-Encoding":           "deflate",
		"Accept-Language":           "en-US,en;q=0.5",
		"Upgrade-Insecure-Requests": "1",
		"Origin":                    "https://www.instagram.com",
		//"Referer":"https://www.instagram.com/accounts/emailsignup/",
		"Connection": "keep-alive",
		"User-Agent": useragent,
	}, OnRequestEnd: func(headers map[string][]string, cookies []*http.Cookie) {
		println("cookies=========================================")
		if cookies != nil {
			for _, cookie := range cookies {
				_cookies[cookie.Name] = cookie.Value
				println(cookie.Name, "\t", cookie.Value)
				if cookie.Name == "csrftoken" {
					secondHeader["X-CSRFToken"] = cookie.Value
					_cookies["csrftoken"] = cookie.Value
					account.CsrfToken = cookie.Value
				} else if cookie.Name == "mid" {
					_cookies["mid"] = cookie.Value
					account.Mid = cookie.Value
				} else if cookie.Name == "rur" {
					_cookies["rur"] = cookie.Value
					account.Rur = cookie.Value
				} else if cookie.Name == "ig_did" {
					_cookies["ig_did"] = cookie.Value
					account.DeviceId = cookie.Value
				}
			}
		}
	}, OnHttpClient: hclient}

	body1 := api.Get(curl1)
	println(curl1, "\t", len(body1))
	body := api.Get(curl)
	for len(body) == 0 {
		time.Sleep(2 * time.Second)
		body = api.Get(curl)
	}

	if len(body) > 0 {
		device_id, device_idState := stringVal(body, `"device_id":"`)
		csrf_token, csrf_tokenState := stringVal(body, `"csrf_token":"`)
		publicKey, keyState := stringVal(body, `"public_key":"`)
		version, versionState := stringVal(body, `"version":"`)
		key_id, keyIdState := stringVal(body, `"key_id":"`)
		if len(account.Mid) > 0 && csrf_tokenState && device_idState && keyState && versionState && keyIdState && len(publicKey) > 0 && len(version) > 0 && len(key_id) > 0 && len(device_id) > 0 && len(csrf_token) > 0 {
			//计算密码
			encKey := EncKey{key_id, version, publicKey, account.Pwd, ""}
			keycache[account.Pwd] = &encKey
			keys.PushBack(account.Pwd)
			for encKey.EncPwd == "" {
				println("wait password to encrypt...")
				time.Sleep(1 * time.Second)
			}

			account.DeviceId = device_id
			account.CsrfToken = csrf_token
			println("DeviceId\t", account.DeviceId)
			secondHeader["referer"] = "https://www.instagram.com/accounts/emailsignup/"
			secondHeader["Content-Type"] = "application/x-www-form-urlencoded"
			secondHeader["X-CSRFToken"] = account.CsrfToken

			ctx := gapi.Ctx{Isdebug: true, Headers: &_headers, Cookies: &_cookies, OnRequestEnd: func(headers map[string][]string, cookies []*http.Cookie) {
				println("headers===========================")
				if headers != nil {
					for k, v := range headers {
						println(k, "\t", v[0])
					}
				}
				println("cookies===========================")
				if cookies != nil {
					for _, cookie := range cookies {
						_cookies[cookie.Name] = cookie.Value
						println(cookie.Name, "\t", cookie.Value)
						if cookie.Name == "csrftoken" {
							secondHeader["X-CSRFToken"] = cookie.Value
						}
					}
				}
			}, OnHttpClient: hclient}
			//email=bluehawk123xx%40qq.com&enc_password=%23PWD_INSTAGRAM_BROWSER%3A6%3A1588833845%3AAdlQABdSoQRbd8BLY1OR%2BWjaKmEcukr4qG94%2B5CnoyRmXig4iiksD7UBcTHJQ6uNwHMyD67TCE38LGw8Z4Zl3FTnAHOvfSkF04sKi5exbtLgDKN3%2BzMZlU7XE4EuFhDMbnrUZ7emN3fJgQ%3D%3D
			//&username=bluehawk123xx&first_name=bluehawk&month=5&day=13&year=1985&seamless_login_enabled=1&tos_version=row
			account.Byear = gapi.Ryear()
			account.Bmonth = gapi.Rmonth()
			account.Bday = gapi.Rday()
			params := url.Values{
				"email":                  {account.Email},
				"enc_password":           {encKey.EncPwd},
				"username":               {account.Username},
				"first_name":             {account.Name},
				"month":                  {account.Bmonth},
				"day":                    {account.Bday},
				"year":                   {account.Byear},
				"client_id":              {account.Mid},
				"seamless_login_enabled": {"1"},
				"tos_version":            {"row"},
			}
			payload := params.Encode()

			//day=13&month=5&year=1985
			payloadAge := url.Values{
				"month": {account.Bmonth},
				"day":   {account.Bday},
				"year":  {account.Byear},
			}.Encode()

			//email=bluehawk123xx%40qq.com&username=&first_name=&opt_into_one_tap=false
			attemptPayloadName := url.Values{
				"email":            {account.Email},
				"username":         {""},
				"first_name":       {""},
				"opt_into_one_tap": {"false"},
			}.Encode()

			//email=bluehawk123xx%40qq.com&enc_password=%23PWD_INSTAGRAM_BROWSER%3A6%3A1588833823%3AAdlQAGhfNUq2hf7k985S4eQFBJ5Z8LFeNsn3UVM7cad2La9bBvUeZD8vlvDNSoa4Y1%2FzWooRhy3lCa8amovWv%2F0KS%2FKgnFSFgfXUOBn3erNNQmSOsxUp2F64ePa%2FxUxRyS8cxS7QCCAp3A%3D%3D
			//&username=bluehawk123xx&first_name=bluehawk&client_id=XrOtTgALAAH_41rOZdmseiVKgXC-&seamless_login_enabled=1&opt_into_one_tap=false
			attemptPayload := url.Values{
				"email":                  {account.Email},
				"enc_password":           {encKey.EncPwd},
				"username":               {account.Username},
				"first_name":             {account.Name},
				"client_id":              {account.Mid},
				"seamless_login_enabled": {"1"},
				"opt_into_one_tap":       {"false"},
			}.Encode()

			println("payload\t", payload)
			println("attemptPayloadName\t", attemptPayloadName)
			println("payloadAge\t", payloadAge)
			println("attemptPayload\t", attemptPayload)

			sendEmailValidCodeUrl := "https://i.instagram.com/api/v1/accounts/send_verify_email/"

			attempt := "https://www.instagram.com/accounts/web_create_ajax/attempt/"
			post30 := ctx.Post31(attempt, attemptPayloadName, secondHeader)
			println("==========post30\t", post30)

			post31 := ctx.Post31(attempt, attemptPayload, secondHeader)
			println("==========post31\t", post31)

			checkAgeUrl := "https://www.instagram.com/web/consent/check_age_eligibility/"
			post32 := ctx.Post31(checkAgeUrl, payloadAge, secondHeader)
			println("==========post32\t", post32)

			post33 := ctx.Post31(attempt, payload, secondHeader)
			println("==========post33\t", post33)
			if !strings.Contains(post33, `"dryrun_passed": true`) {
				println("post33 dryrun_passed fail")
				return
			}

			var sendEmailHeaders = map[string]string{
				"device_id":                      account.Mid,
				"email":                          account.Email,
				"access-control-request-headers": "x-csrftoken,x-ig-app-id,x-ig-www-claim,x-instagram-ajax",
				"content-security-policy":        "report-uri https://www.instagram.com/security/csp_report/; default-src 'self' https://www.instagram.com; img-src https: data: blob:; font-src https: data:; media-src 'self' blob: https://www.instagram.com https://*.cdninstagram.com https://*.fbcdn.net; manifest-src 'self' https://www.instagram.com; script-src 'self' https://instagram.com https://www.instagram.com https://*.www.instagram.com https://*.cdninstagram.com wss://www.instagram.com https://*.facebook.com https://*.fbcdn.net https://*.facebook.net 'unsafe-inline' 'unsafe-eval' blob:; style-src 'self' https://*.www.instagram.com https://www.instagram.com 'unsafe-inline'; connect-src 'self' https://instagram.com https://www.instagram.com https://*.www.instagram.com https://graph.instagram.com https://*.graph.instagram.com https://*.cdninstagram.com https://api.instagram.com https://i.instagram.com wss://www.instagram.com wss://edge-chat.instagram.com https://*.facebook.com https://*.fbcdn.net https://*.facebook.net chrome-extension://boadgeojelhgndaghljhdicfkmllpafd blob:; worker-src 'self' blob: https://www.instagram.com; frame-src 'self' https://instagram.com https://www.instagram.com https://staticxx.facebook.com https://www.facebook.com https://web.facebook.com https://connect.facebook.net https://m.facebook.com; object-src 'none'; upgrade-insecure-requests",
			}

			for k, v := range secondHeader {
				println(k, v)
				sendEmailHeaders[k] = v
			}

			emailBody1 := ctx.Request(http.MethodOptions, sendEmailValidCodeUrl, "", nil, secondHeader)
			println("emailBody1\t", emailBody1)

			for k, v := range secondHeader {
				println(k, v)
				sendEmailHeaders[k] = v
			}

			emailBody := ctx.Post31(sendEmailValidCodeUrl, fmt.Sprintf("device_id=%s&email=%s", account.Mid, account.Email), sendEmailHeaders)
			println("emailBody\t", emailBody)

			code, b := EmailCode(account.Email, client)
			if b {
				println("code\t", code)
				confirmationCodeUrl := "https://i.instagram.com/api/v1/accounts/check_confirmation_code/"
				confirmationBody := ctx.Post31(confirmationCodeUrl, fmt.Sprintf("code=%s&device_id=%s&email=%s", code, account.Mid, account.Email), sendEmailHeaders)
				println("confirmationBody\t", confirmationBody)
				//{"signup_code": "SOhN0m1e", "status": "ok"}
				if strings.Contains(confirmationBody, `"signup_code": "`) {
					val, b2 := stringVal(confirmationBody, `"signup_code": "`)
					if b2 {
						code = val
					}
				}
			} else {
				println("no email code received!")
				return
			}

			params["force_sign_up_code"] = []string{code}
			registerParams := params.Encode()
			url := "https://www.instagram.com/accounts/web_create_ajax/"
			secondBody := ctx.Post31(url, registerParams, secondHeader)
			//ds_user_id=34587771054
			println("==========secondBody\t", secondBody)
			if !strings.Contains(secondBody, `"errors":`) && !strings.Contains(secondBody, "The IP address you are using has been flagged as an open proxy") && !strings.Contains(secondBody, "force_sign_up_code") {

				status, statusState := stringVal(secondBody, `"status": "`)
				if !statusState {
					println("创建账号失败")
				}
				accjson := payload
				b, err := json.Marshal(account)
				if err == nil {
					accjson = string(b)
				}
				if status != "fail" {
					println("创建账号成功")
					//os.File{}
					//gapi.Appendfile("acc.txt",fmt.Sprintf("success\t%s\t%s\t%d","hk---ip",accjson,proxy_port))
					if strings.Contains(secondBody, `"account_created": true, "user_id": "`) {
						saveLog("acc_success.txt", fmt.Sprintf("success\t%s\t%s\t%d", "hk---ip", accjson, proxy_port))
					} else {
						saveLog("acc.txt", fmt.Sprintf("success\t%s\t%s\t%d", "hk---ip", accjson, proxy_port))
					}

				} else if status == "fail" {
					println("创建账号失败")
					//gapi.Appendfile("acc.txt",fmt.Sprintf("fail\t%s\t%s","hk---ip",accjson))
					saveLog("acc.txt", fmt.Sprintf("fail\t%s\t%s", "hk---ip", accjson))
				}
			} else {
				println("创建账号失败", secondBody)
			}
		}
	}
	//println(body)
}

func saveLog(path, content string) {
	saveLoglock.Lock()
	defer saveLoglock.Unlock()
	gapi.Appendfile(path, content)
}

func accinfo(api gapi.Ctx) (string, string, string, string, bool) {
	infoBody := api.Get("http://61.128.146.67:18080/tdata/clientUserList?num=1")
	println(infoBody)
	email, emailState := stringVal(infoBody, `,"email":"`)
	pwd, pwdState := stringVal(infoBody, `,"pwd":"`)
	username, usernameState := stringVal(infoBody, `,"wechatname":"`)
	nickname, nicknameState := stringVal(infoBody, `,"nickname":"`)
	if !emailState || !pwdState || !usernameState || !nicknameState {
		return "", "", "", "", true
	}
	println(email, pwd, username, nickname)
	return email, pwd, username, nickname, false
}

func rundomuser(api gapi.Ctx, acc *Account) bool {
	body := api.Get("https://randomuser.me/api/")
	if body != "" {
		first, firstState := stringVal(body, `"first":"`)
		last, lastState := stringVal(body, `"last":"`)
		username, usernameState := stringVal(body, `"username":"`)
		if !firstState || !lastState || !usernameState {
			return false
		}
		acc.Username = fmt.Sprintf("%sbkl", username)
		acc.Name = fmt.Sprintf("%s %s", first, last)
		acc.Email = fmt.Sprintf("%sbkl@gmail.com", username)
		return true
	}
	return false
}

func request(api gapi.Ctx, url string, times int) string {
	for i := 0; i < times; i++ {
		body := api.Get(url)
		if body != "" {
			return body
		} else {
			time.Sleep(1 * time.Second)
		}
	}
	return ""
}

func cmd2str2(cmd string) string {
	switch runtime.GOOS {
	case "darwin":
		{
			output, err := exec.Command(cmd).Output()
			println("err\t", err, cmd)
			return string(output)
		}
	case "windows":
		{
			output, err := exec.Command("bash", "-c", cmd).Output()
			println("err\t", err, cmd)
			return string(output)
		}
	case "linux":
		{
			output, err := exec.Command("bash", "-c", cmd).Output()
			println("err\t", err, cmd)
			return string(output)
		}
	}
	return ""
}

func KillPid(pid string) {
	switch runtime.GOOS {
	case "darwin":
		{
			exec.Command("kill", "-9", pid).Run()
			break
		}
	case "windows":
		{
			exec.Command("taskkill", "/pid", pid, "-f").Run()
			break
		}
	case "linux":
		{
			exec.Command("kill", "-9", pid).Run()
			break
		}
	}
}

func closeProByPort(server_port string) {
	pid := cmd2str2(fmt.Sprintf(closeCmdFmt, server_port))
	println("netstat -anto\t" + pid)
	if len(pid) <= 0 {
		return
	}
	if len(pid) > 0 {
		KillPid(pid)
	}
}

func bootPro(path string, bootstr []string) {
	cmd := exec.Cmd{Path: path, Args: append([]string{path}, bootstr...)}
	go func() { cmd.Run() }()
}

func ChangeProxy2s(server_port string, fs ...string) {
	closeProByPort(server_port)
	proxyinfo := append([]string{"-L=socks5://127.0.0.1:" + server_port}, fs...)
	print(proxyinfo[0], proxyinfo[1])
	bootPro(proxybin, proxyinfo)
}

func ip138(api gapi.Ctx, dstip string) string {
	for {
		info := request(api, "https://2020.ipchaxun.com/", 3)
		if len(info) > 0 {
			ip, ipState := stringVal(info, `"ip":"`)
			if ipState && len(dstip) > 0 && ip == dstip {
				return ip
			} else {
				return ip
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func proxyRunSmart(localPort string, port int, hclient *gapi.HClient, run ProxyRun) {
	useragent := gapi.RandUserAgentPc()
	api := gapi.Ctx{Isdebug: true, Headers: &map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Accept-Encoding":           "deflate",
		"Accept-Language":           "en-US,en;q=0.5",
		"Upgrade-Insecure-Requests": "1",
		"Origin":                    "https://www.instagram.com",
		"Connection":                "keep-alive",
		"User-Agent":                useragent,
	}, OnHttpClient: hclient}
	serverip := ip138(api, "")
	println("current ip \t" + serverip)
	if run != nil {
		run(serverip)
	}
}

//taskkill/F /im insgost.exe
