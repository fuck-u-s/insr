package hapi

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"strings"
	//	"io/ioutil"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"time"
)

type StringMap map[string]string

type RebootProxyCallBack func(ppinfo string, authinfo string, serial string, ischange bool)

type xmlMapEntry struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type Ctx struct {
	Modem_host  string
	Username    string
	Password    string
	Session_id  string
	Logged_in   bool
	Login_token string
	Isdebug     bool
	Serial      string
	Iccid       string

	Server_ip string
	Sport     string

	Lmd5     string
	Ppinfo   string
	Amd5     string
	Authinfo string

	Version string

	noServiceTimes int16
}

func Urlencode(val string) string {
	return url.QueryEscape(val)
}

func (t *Ctx) Host(host, username, password string) {
	t.Modem_host = host
	t.Username = username
	t.Password = password
}

func (m *StringMap) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*m = StringMap{}
	for {
		var e xmlMapEntry

		err := d.Decode(&e)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		(*m)[e.XMLName.Local] = e.Value
	}
	return nil
}

func md5V(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func b64(msg string) string {
	return base64.URLEncoding.EncodeToString([]byte(msg))
}

func b64_sha256bs(message []byte) string {
	hash := sha256.New()
	hash.Write(message)
	bytes := hash.Sum(nil)
	hashCode := hex.EncodeToString(bytes)
	println(hashCode)
	code := base64.URLEncoding.EncodeToString([]byte(hashCode))
	return code
}

func b64_sha256(message string) string {
	println(message)
	bs := b64_sha256bs([]byte(message))
	println(bs)
	return bs
}

func checkOk(body string) bool {
	return strings.Contains(body, "<response>OK</response>")
}

func checkCode(body string) bool {
	return strings.Contains(body, "<code>")
}

func (t *Ctx) api_base_url(url string) string {
	url1 := fmt.Sprintf("http://%s/api%s", t.Modem_host, url)
	if t.Isdebug {
		println(url1)
	}
	return url1
}

func (t *Ctx) common_headers() map[string]string {
	if t.Login_token != "" {
		return map[string]string{
			"bin-Version":                t.Version,
			"X-Requested-With":           "XMLHttpRequest",
			"__RequestVerificationToken": t.Login_token,
		}
	} else {
		return map[string]string{
			"bin-Version":      t.Version,
			"X-Requested-With": "XMLHttpRequest",
			//"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			//"Accept-Encoding": "gzip, deflate",
			//"Accept-Language": "zh-CN,zh;q=0.9",
			//"Upgrade-Insecure-Requests": "1",
			//"Connection": "keep-alive",
			//"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Safari/537.36",
		}
	}
}
func (t *Ctx) build_cookies() map[string]string {
	if t.Session_id != "" {
		return map[string]string{
			"SessionID": t.Session_id,
		}
	} else {
		return map[string]string{}
	}
}

func (t *Ctx) Get(url string) string {
	return t.Get2(url, "")
}
func (t *Ctx) Get2(url string, data string) string {
	return t.Get4(url, data, make(map[string]string), make(map[string]string))
}

func (t *Ctx) Get4(url string, data string, cks map[string]string, hds map[string]string) string {
	if t.Isdebug {
		println("Get url", url)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	var req *http.Request
	if data == "" {
		req, _ = http.NewRequest(http.MethodGet, url, nil)
	} else {
		req, _ = http.NewRequest(http.MethodGet, url, strings.NewReader(data))
	}

	cookies := t.build_cookies()
	for k, v := range cookies {
		if t.Isdebug {
			println("add cookie", k, v)
		}
		req.AddCookie(&http.Cookie{Name: k, Value: v, HttpOnly: true})
	}
	for k, v := range cks {
		if t.Isdebug {
			println("add cookie", k, v)
		}
		req.AddCookie(&http.Cookie{Name: k, Value: v, HttpOnly: true})
	}
	headers := t.common_headers()
	for k, v := range headers {
		if t.Isdebug {
			println("add header", k, v)
		}
		req.Header.Add(k, v)
	}
	for k, v := range hds {
		if t.Isdebug {
			println("add header", k, v)
		}
		req.Header.Add(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		println(err)
		return ""
	}
	defer resp.Body.Close()

	if resp.Header.Get("__RequestVerificationToken") != "" {
		toks := strings.Split(resp.Header.Get("__RequestVerificationToken"), "#")
		if len(toks) >= 1 {
			t.Login_token = toks[len(toks)-1]
		}
	}

	rcookies := resp.Cookies()
	for _, cookie := range rcookies {
		if cookie.Name == "SessionID" {
			t.Session_id = cookie.Value
		}
	}

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

func (t *Ctx) Post(url string) string {
	return t.Post2(url, "")
}
func (t *Ctx) Post2(url string, data string) string {
	return t.Post4(url, data, make(map[string]string), make(map[string]string))
}

func (t *Ctx) Post31(url string, data string, hds map[string]string) string {
	return t.Post4(url, data, make(map[string]string), hds)
}

func (t *Ctx) Post32(url string, data string, cks map[string]string) string {
	return t.Post4(url, data, cks, make(map[string]string))
}

func (t *Ctx) Post4(url string, data string, cks map[string]string, hds map[string]string) string {
	if t.Isdebug {
		println("post url", url)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	var req *http.Request
	req, _ = http.NewRequest(http.MethodPost, url, strings.NewReader(data))
	reqcookies := t.build_cookies()
	for k, v := range reqcookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v, HttpOnly: true})
	}
	for k, v := range cks {
		req.AddCookie(&http.Cookie{Name: k, Value: v, HttpOnly: true})
	}
	headers := t.common_headers()
	for k, v := range headers {
		if t.Isdebug {
			println("add header", k, v)
		}
		req.Header.Add(k, v)
	}
	for k, v := range hds {
		if t.Isdebug {
			println("add header", k, v)
		}
		req.Header.Add(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.Header.Get("__RequestVerificationToken") != "" {
		toks := strings.Split(resp.Header.Get("__RequestVerificationToken"), "#")
		if len(toks) >= 1 {
			t.Login_token = toks[len(toks)-1]
		}
	}
	rcookies := resp.Cookies()
	for _, cookie := range rcookies {
		if cookie.Name == "SessionID" {
			t.Session_id = cookie.Value
		}
	}

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

func (t *Ctx) xml2map(str string) map[string]string {
	dataMap := make(map[string]string)
	err := xml.Unmarshal([]byte(str), (*StringMap)(&dataMap))
	if err != nil {
		println("parse xml error")
	}
	return dataMap
}

func AsJson(s string) map[string]string {
	dataMap := make(map[string]string)
	err := json.Unmarshal([]byte(s), (*StringMap)(&dataMap))
	if err != nil {
		println("parse json error", err)
	}
	return dataMap
}

func (t *Ctx) json2map(str string) map[string]string {
	dataMap := make(map[string]string)
	err := json.Unmarshal([]byte(str), (*StringMap)(&dataMap))
	if err != nil {
		println("parse json error", err)
	}
	return dataMap
}

func (t *Ctx) body2map(body string) map[string]string {
	if body != "" && strings.Contains(body, "<response>") {
		start_index := strings.Index(body, "<response>")
		response_str := body[start_index:]
		return t.xml2map(response_str)
	} else if body != "" && strings.Contains(body, `<?xml Version="1.0" encoding="UTF-8"?>`) {
		start_index := strings.Index(body, `<?xml Version="1.0" encoding="UTF-8"?>`) + len(`<?xml Version="1.0" encoding="UTF-8"?>`) + 1
		response_str := body[start_index:]
		return t.xml2map(response_str)
	} else if body != "" {
		return t.xml2map(body)
	}
	return nil
}

func (t *Ctx) get_session_token_info() map[string]string {
	body := t.Get(t.api_base_url("/webserver/SesTokInfo"))
	return t.body2map(body)
}

func (t *Ctx) initCtx() bool {
	t.Session_id = ""
	t.Login_token = ""
	t.Logged_in = false
	t.Server_ip = ""
	t.Sport = ""
	t.Serial = ""
	t.Isdebug = true
	t.noServiceTimes = 0

	data := t.get_session_token_info()
	if data != nil {
		t.Session_id = data["SesInfo"]
		t.Login_token = data["TokInfo"]

		return true
	}

	return false
}

func (t *Ctx) disableAutoupdateConfig() bool {
	xml_data := `<?xml Version="1.0" encoding="UTF-8"?><request><auto_update>0</auto_update><ui_download>0</ui_download></request>`
	body := t.Post2(t.api_base_url("/online-update/autoupdate-config"), xml_data)
	return !checkCode(body)
}

func (t *Ctx) deviceBasicInformation() bool {
	xml_data := `<?xml Version="1.0" encoding="UTF-8"?><request><restore_default_status>0</restore_default_status></request>`
	body := t.Post2(t.api_base_url("/device/basic_information"), xml_data)
	return !checkCode(body)
}

func (t *Ctx) changePassword() bool {
	xml_data := fmt.Sprintf(`<?xml Version="1.0" encoding="UTF-8"?><request><Username>admin</Username><currentpassword>admin</currentpassword><newpassword>%s</newpassword></request>`, t.Password)
	body := t.Post2(t.api_base_url("/user/password_scram"), xml_data)
	return !checkCode(body)
}

func (t *Ctx) tryPassword(password string) bool {
	url := t.api_base_url("/user/login")
	password_value := b64_sha256(t.Username + b64_sha256(password) + t.Login_token)
	xml_data := `
    <?xml Version:"1.0" encoding="UTF-8"?>
    <request>
        <Username>%s</Username>
        <Password>%s</Password>
        <password_type>4</password_type>
    </request>
    `
	xml_data = fmt.Sprintf(xml_data, t.Username, password_value)
	body := t.Post2(url, xml_data)
	//	println(body)
	if strings.Contains(body, "<response>OK</response>") {
		t.Logged_in = true
		return true
	}
	t.Logged_in = false
	return false
}

func (t *Ctx) quickLogin() bool {
	if t.Logged_in && !t.status() {
		return true
	}
	if !t.initCtx() {
		return false
	}
	if t.tryPassword("admin") {
		autoconfig := t.disableAutoupdateConfig()
		basicInfo := t.deviceBasicInformation()
		changePwd := t.changePassword()
		if t.Isdebug {
			println("init Password,", autoconfig, basicInfo, changePwd)
		}
		t.initCtx()
	}
	loginStatus := t.tryPassword(t.Password)
	if loginStatus {
		t.wifidisable()
		//t.netmod4G()
	}
	return loginStatus
}

func (t *Ctx) netmod3G() bool {
	for i := 0; i < 3; i++ {
		if t.netmod3G_inner() {
			return true
		} else {
			time.Sleep(1 * time.Second)
		}
	}
	return false
}

func (t *Ctx) Sendsms(dest, msg string) bool {
	for !t.quickLogin() {
		time.Sleep(5 * time.Second)
		println("login fail,wait 5 seconds")
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	xml := `
	<request>
	<Index>-1</Index>
	<Phones>
	<Phone>%s</Phone>
	</Phones>
	<Sca></Sca>
	<Content>%s</Content>
	<Length>%d</Length>
	<Reserved>1</Reserved>
	<Date>%s</Date>
	</request>`
	xml = fmt.Sprintf(xml, dest, msg, len(msg), now)
	println(xml)
	body := t.Post2(t.api_base_url("/sms/send-sms"), xml)
	if t.Isdebug {
		println(body)
	}
	return checkOk(body)
}

func (t *Ctx) DeleteSms(index int) bool {
	xml := fmt.Sprintf(`<?xml Version:"1.0" encoding="UTF-8"?><request><Index>%d</Index></request>`, index)
	body := t.Post2(t.api_base_url("/sms/delete-sms"), xml)
	if t.Isdebug {
		println(body)
	}
	return checkOk(body)
}

func (t *Ctx) Smslist() {
	xml := `
	<request>
	<PageIndex>1</PageIndex>
	<ReadCount>100</ReadCount>
	<BoxType>1</BoxType>
	<SortType>0</SortType>
	<Ascending>0</Ascending>
	<UnreadPreferred>1</UnreadPreferred>
	</request>`
	body := t.Post2(t.api_base_url("/sms/sms-list"), xml)
	if t.Isdebug {
		println(body)
	}
	t.body2map(body)
}

//<?xml Version: "1.0" encoding="UTF-8"?><request><NetworkMode>02</NetworkMode><NetworkBand>3FFFFFFF</NetworkBand><LTEBand>7FFFFFFFFFFFFFFF</LTEBand></request>
func (t *Ctx) netmod3G_inner() bool {
	xml := `<?xml Version: "1.0" encoding="UTF-8"?><request><NetworkMode>02</NetworkMode><NetworkBand>3FFFFFFF</NetworkBand><LTEBand>7FFFFFFFFFFFFFFF</LTEBand></request>`
	body := t.Post2(t.api_base_url("/net/net-mode"), xml)
	if t.Isdebug {
		println(body)
	}
	return checkOk(body)
}

func (t *Ctx) netmod4G() bool {
	for i := 0; i < 1; i++ {
		if t.netmod4G_inner() {
			return true
		} else {
			time.Sleep(1 * time.Second)
		}
	}
	return false
}

func (t *Ctx) netmod4G_inner() bool {
	xml := `<?xml Version: "1.0" encoding="UTF-8"?><request><NetworkMode>03</NetworkMode><NetworkBand>3FFFFFFF</NetworkBand><LTEBand>7FFFFFFFFFFFFFFF</LTEBand></request>`
	body := t.Post2(t.api_base_url("/net/net-mode"), xml)
	if t.Isdebug {
		println(body)
	}
	return checkOk(body)
}

func (t *Ctx) wifidisable() bool {
	xml := `<?xml Version: "1.0" encoding="UTF-8"?><request><radios><radio><ID>InternetGatewayDevice.X_Config.Wifi.Radio.1.</ID><index>0</index><wifienable>0</wifienable></radio></radios></request>`
	body := t.Post2(t.api_base_url("/wlan/status-switch-settings"), xml)
	if t.Isdebug {
		println(body)
	}
	return checkOk(body)
}

func (t *Ctx) netmodAuto() bool {
	for i := 0; i < 3; i++ {
		if t.netmodAuto_inner() {
			return true
		} else {
			time.Sleep(1 * time.Second)
		}
	}
	return false
}

func (t *Ctx) netmodAuto_inner() bool {
	xml := `<?xml Version: "1.0" encoding="UTF-8"?><request><NetworkMode>00</NetworkMode><NetworkBand>3FFFFFFF</NetworkBand><LTEBand>7FFFFFFFFFFFFFFF</LTEBand></request>`
	body := t.Post2(t.api_base_url("/net/net-mode"), xml)
	if t.Isdebug {
		println(body)
	}
	return checkOk(body)
}

func (t *Ctx) status() bool {
	body := t.Get(t.api_base_url("/monitoring/status"))
	if t.Isdebug {
		println(body)
	}
	return checkCode(body)
}

func (t *Ctx) information() map[string]string {
	if t.quickLogin() {
		body := t.Get(t.api_base_url("/device/information"))
		if checkCode(body) {
			t.Logged_in = false
			return nil
		}
		if t.Isdebug {
			println(body)
		}
		dataMap := t.body2map(body)
		return dataMap
	}
	return nil
}

func (t *Ctx) deviceSerial() string {
	for {
		dataMap := t.information()
		if dataMap != nil {
			if dataMap["workmode"] == "NO SERVICE" || dataMap["WanIPAddress"] == "0.0.0.0" {
				t.noServiceTimes += 1
				if t.noServiceTimes >= 72 {
					exec.Command("reboot").Run()
					time.Sleep(5 * time.Second)
				} else {
					time.Sleep(5 * time.Second)
					if t.noServiceTimes > 0 && t.noServiceTimes%5 == 0 {
						t.netmodAuto()
					}
					continue
				}
			} else {
				t.noServiceTimes = 0
			}
			//		t.Serial = fmt.Sprintf("%s_%s_%s", dataMap["Imsi"], dataMap["Imei"], md5V(fmt.Sprintf("%s-%s", dataMap["Imsi"], dataMap["Imei"])))
			t.Serial = fmt.Sprintf("%s", dataMap["Imei"])
			gargs := make([]string, len(dataMap))
			i := 0
			for k, v := range dataMap {
				gargs[i] = fmt.Sprintf("%s=%s", k, Urlencode(v))
			}
			t.Iccid = strings.Join(gargs, "&")
			return t.Serial
		} else {
			time.Sleep(5 * time.Second)
		}
	}
	return ""
}

func (t *Ctx) sinfo() bool {
	body := t.Get("http://e8732h155.oss-cn-hangzhou.aliyuncs.com/config0.2.text")
	if t.Isdebug {
		println(body)
	}
	if body != "" {
		dataMap := t.body2map(body)
		if len(dataMap["ip"]) > 1 && len(dataMap["port"]) > 1 {
			t.Server_ip = dataMap["ip"]
			t.Sport = dataMap["port"]
			return true
		}
	}
	return false
}

func (t *Ctx) cfgInfo() bool {
	t.deviceSerial()
	for len(t.Serial) == 0 {
		time.Sleep(1 * time.Second)
		t.deviceSerial()
	}

	//t.netmodAuto()
	t.sinfo()
	for len(t.Server_ip) == 0 || len(t.Sport) == 0 {
		time.Sleep(1 * time.Second)
		t.sinfo()
	}
	cfgurl := fmt.Sprintf("http://%s:%s/api/onboot/%s?iccid=%s", t.Server_ip, t.Sport, t.Serial, t.Iccid)
	body := t.Get(cfgurl)
	for body == "" {
		time.Sleep(1 * time.Second)
		body = t.Get(cfgurl)
	}
	dataMap := t.json2map(body)
	protocol := dataMap["protocol"]
	user := dataMap["user"]
	passwd := dataMap["passwd"]
	server := dataMap["server"]
	server_port := dataMap["server_port"]
	dns := dataMap["dns"]
	token := dataMap["token"]
	type1 := "tcp"
	if strings.Contains(protocol, "kcp") || strings.Contains(protocol, "quic") || strings.Contains(protocol, "ssu") {
		type1 = "udp"
	}

	t.Ppinfo = fmt.Sprintf("%s://%s:%s@%s:%s?dns=%s", protocol, user, passwd, "", server_port, dns)
	auth := fmt.Sprintf("[common]\nserver_addr=%s\nserver_port=%s\nprivilege_token=%s\n[ssh%s%s]\ntype=%s\nprivilege_mode=true\nuse_encryption=true\nlocal_port=%s\nlocal_ip=%s\nremote_port=%s\npool_count=3", server, "7000", token, server_port, type1, type1, server_port, "127.0.0.1", server_port)
	t.Authinfo = auth //b64(auth)
	lmd5 := md5V(t.Ppinfo)
	amd5 := md5V(auth)

	if t.Isdebug {
		println(t.Lmd5, t.Ppinfo)
		println(t.Amd5, t.Authinfo)
	}

	ischange := lmd5 != t.Lmd5 || amd5 != t.Amd5
	t.Amd5 = amd5
	t.Lmd5 = lmd5

	return ischange
}

func (t *Ctx) rebootProxy(callback RebootProxyCallBack, ischange bool) {
	go func() {
		callback(t.Ppinfo, t.Authinfo, t.Serial, ischange)
	}()
}

func (t *Ctx) heartval() string {
	hurl := fmt.Sprintf("http://%s:%s/api/onswitch/%s/end", t.Server_ip, t.Sport, t.Serial)
	body := t.Get(hurl)
	//	println(hurl, body)
	return body
}

func (t *Ctx) bootProxy(callback RebootProxyCallBack) bool {
	var pretime int64 = 0
	var times int64 = 1
	for {
		unixtime := time.Now().Unix()
		if unixtime-pretime >= 60 {
			pretime = unixtime
			go func() {
				if t.cfgInfo() {
					t.rebootProxy(callback, true)
				}
			}()
		}

		for len(t.Serial) == 0 {
			time.Sleep(1 * time.Second)
		}
		for len(t.Server_ip) == 0 || len(t.Sport) == 0 {
			time.Sleep(1 * time.Second)
		}
		if times%20 == 0 {
			times = 0
			t.quickLogin()
		}
		if t.heartval() == "ok" {
			t.netmod3G()
			//t.netmod4G()
			t.netmodAuto()
			t.rebootProxy(callback, false)
		}
		times += 1
		time.Sleep(1 * time.Second)
	}
}

func (t *Ctx) ChangeIp(callback RebootProxyCallBack) bool {
	for {
		t.deviceSerial()
		t.netmod3G()
		t.netmod4G()
		callback(t.Ppinfo, t.Authinfo, t.Serial, false)
		time.Sleep(10 * time.Second)
	}
}
