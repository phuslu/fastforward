// {{.Version}} - updated at {{.UpdatedAt.Format "2006-01-02T15:04:05Z07:00"}}

var proxy = '{{.Scheme}} {{.Host}}'
var direct = 'DIRECT'

var prelude = {
	// wifi hotpot
	"captive.apple.com":0,
	"www.msftconnecttest.com":0,
	"www.msftncsi.com":0,
	// direct domains
	"notepad.nz":0,
	"phus.lu":0,
	"golang.org":0,
	// proxy doamins
	"facebook.com":1,
	"googlevideo.com":1,
	"linkedin.com":1,
	"pornhub.com":1,
	"twimg.com":1,
	"twitter.com":1,
	"youtube.com":1,
	"ytimg.com":1,
	// dark web
	"onion":1
}

var reserved = [0xa000000,0xb000000,0x7f000000,0x80000000,0xa9fe0000,0xa9ff0000,0xac100000,0xac200000,0xc0a80000,0xc0a90000,0xf0000000,0xfa000000]

var iplist = {{ iplist "https://cdn.jsdelivr.net/gh/phuslu/iplist/sg.txt" }}

function FindProxyForURL(_, host) {
	var i
	var tld = host
	do {
		if ((v = prelude[tld]) !== undefined)
			return v ? proxy : direct
		i = tld.indexOf('.') + 1
		tld = tld.slice(i)
	} while (i >= 1)

	var ipaddr = dnsResolve(host)
	if (!ipaddr)
		return proxy

	var b = ipaddr.split('.')
	var ip = (((b[0]*256+(+b[1]))*256+(+b[2]))*256)+(+b[3])

	var intranet = false
	for (i = 0; i < reserved.length/2; i++)
		if (ip >= reserved[2 * i] && ip < reserved[2 * i + 1]) {
			intranet = true
			break
		}

	if (intranet || ip == 0)
		return direct

	var n = iplist.length
	i = 0
	while (i < n - 2) {
		m = ((i + n) >> 1) & 0xfffe
		v = iplist[m]
		if (v <= ip) {
			i = m
		} else {
			n = m
		}
	}

	if (i < iplist.length && ip <= iplist[i] + iplist[i+1])
		return direct

	return proxy
}
