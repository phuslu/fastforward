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
	"phncdn.com":1,
	"pornhub.com":1,
	"twimg.com":1,
	"twitter.com":1,
	"youtube.com":1,
	"ytimg.com":1,
	// dark web
	"onion":1
}

function FindProxyForURL(_, host) {
	var i
	var tld = host
	do {
		if ((v = prelude[tld]) !== undefined)
			return v ? proxy : direct
		i = tld.indexOf('.') + 1
		tld = tld.slice(i)
	} while (i >= 1)

	return direct
}
