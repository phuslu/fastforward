package main

import (
	"context"
	"errors"
	"net"

	"github.com/oschwald/maxminddb-golang"
)

type GeoResolver struct {
	Resolver     *Resolver
	CityReader   *maxminddb.Reader
	ISPReader    *maxminddb.Reader
	DomainReader *maxminddb.Reader
}

func (r *GeoResolver) LookupCity(ctx context.Context, ip net.IP) (string, string, string, error) {
	if r.CityReader == nil {
		return "", "", "", errors.New("no maxmind city database found")
	}

	if ip == nil {
		return "", "", "", errors.New("invalid ip address")
	}

	var record struct {
		Country struct {
			GeoNameID uint   `maxminddb:"geoname_id"`
			ISOCode   string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			GeoNameID uint `maxminddb:"geoname_id"`
			Names     struct {
				EN string `maxminddb:"en"`
			} `maxminddb:"names"`
		} `maxminddb:"city"`
		Subdivisions []struct {
			GeoNameID uint   `maxminddb:"geoname_id"`
			IsoCode   string `maxminddb:"iso_code"`
			Names     struct {
				EN string `maxminddb:"en"`
			} `maxminddb:"names"`
		} `maxminddb:"subdivisions"`
	}

	err := r.CityReader.Lookup(ip, &record)

	var region string
	if len(record.Subdivisions) != 0 {
		region = record.Subdivisions[0].Names.EN
	}

	return record.Country.ISOCode, region, record.City.Names.EN, err
}

func (r *GeoResolver) LookupISP(ctx context.Context, ip net.IP) (string, error) {
	if r.ISPReader == nil {
		return "", errors.New("no maxmind isp database found")
	}

	if ip == nil {
		return "", errors.New("invalid ip address")
	}

	var record struct {
		AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
		ISP                          string `maxminddb:"isp"`
		MobileCountryCode            string `maxminddb:"mobile_country_code"`
		MobileNetworkCode            string `maxminddb:"mobile_network_code"`
		Organization                 string `maxminddb:"organization"`
		AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	}

	err := r.ISPReader.Lookup(ip, &record)

	return record.ISP, err
}

func (r *GeoResolver) LookupDomain(ctx context.Context, ip net.IP) (string, error) {
	if r.DomainReader == nil {
		return "", errors.New("no maxmind domain database found")
	}

	if ip == nil {
		return "", errors.New("invalid ip address")
	}

	var record struct {
		Domain string `maxminddb:"domain"`
	}

	err := r.DomainReader.Lookup(ip, &record)

	return record.Domain, err
}

func IsBogusChinaIP(ip net.IP) (ok bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	n := ((uint(ip4[0])<<8+uint(ip4[1]))<<8+uint(ip4[2]))<<8 + uint(ip4[3])

	_, ok = bogusChinaIP[n]
	return
}

var bogusChinaIP = map[uint]bool{
	((10<<8+10)<<8+10)<<8 + 10:     true,
	((101<<8+226)<<8+10)<<8 + 8:    true,
	((104<<8+239)<<8+213)<<8 + 7:   true,
	((110<<8+249)<<8+209)<<8 + 42:  true,
	((111<<8+11)<<8+208)<<8 + 2:    true,
	((111<<8+175)<<8+221)<<8 + 58:  true,
	((112<<8+132)<<8+230)<<8 + 179: true,
	((113<<8+11)<<8+194)<<8 + 190:  true,
	((113<<8+12)<<8+83)<<8 + 4:     true,
	((113<<8+12)<<8+83)<<8 + 5:     true,
	((114<<8+112)<<8+163)<<8 + 232: true,
	((114<<8+112)<<8+163)<<8 + 254: true,
	((120<<8+192)<<8+83)<<8 + 163:  true,
	((120<<8+209)<<8+138)<<8 + 64:  true,
	((123<<8+125)<<8+81)<<8 + 12:   true,
	((123<<8+126)<<8+249)<<8 + 238: true,
	((123<<8+129)<<8+254)<<8 + 11:  true,
	((123<<8+129)<<8+254)<<8 + 12:  true,
	((123<<8+129)<<8+254)<<8 + 13:  true,
	((123<<8+129)<<8+254)<<8 + 14:  true,
	((123<<8+129)<<8+254)<<8 + 15:  true,
	((123<<8+129)<<8+254)<<8 + 16:  true,
	((123<<8+129)<<8+254)<<8 + 17:  true,
	((123<<8+129)<<8+254)<<8 + 18:  true,
	((123<<8+129)<<8+254)<<8 + 19:  true,
	((124<<8+232)<<8+132)<<8 + 94:  true,
	((125<<8+211)<<8+213)<<8 + 130: true,
	((125<<8+211)<<8+213)<<8 + 131: true,
	((125<<8+211)<<8+213)<<8 + 132: true,
	((125<<8+211)<<8+213)<<8 + 133: true,
	((125<<8+211)<<8+213)<<8 + 134: true,
	((125<<8+76)<<8+239)<<8 + 244:  true,
	((125<<8+76)<<8+239)<<8 + 245:  true,
	((127<<8+0)<<8+0)<<8 + 2:       true,
	((180<<8+153)<<8+103)<<8 + 224: true,
	((180<<8+168)<<8+41)<<8 + 175:  true,
	((183<<8+207)<<8+232)<<8 + 253: true,
	((183<<8+221)<<8+242)<<8 + 172: true,
	((183<<8+221)<<8+250)<<8 + 11:  true,
	((183<<8+224)<<8+40)<<8 + 24:   true,
	((198<<8+105)<<8+254)<<8 + 11:  true,
	((202<<8+100)<<8+220)<<8 + 54:  true,
	((202<<8+100)<<8+68)<<8 + 117:  true,
	((202<<8+102)<<8+110)<<8 + 203: true,
	((202<<8+102)<<8+110)<<8 + 204: true,
	((202<<8+102)<<8+110)<<8 + 205: true,
	((202<<8+106)<<8+1)<<8 + 2:     true,
	((202<<8+106)<<8+199)<<8 + 34:  true,
	((202<<8+106)<<8+199)<<8 + 35:  true,
	((202<<8+106)<<8+199)<<8 + 36:  true,
	((202<<8+106)<<8+199)<<8 + 37:  true,
	((202<<8+106)<<8+199)<<8 + 38:  true,
	((202<<8+98)<<8+24)<<8 + 121:   true,
	((202<<8+98)<<8+24)<<8 + 122:   true,
	((202<<8+98)<<8+24)<<8 + 123:   true,
	((202<<8+98)<<8+24)<<8 + 124:   true,
	((202<<8+98)<<8+24)<<8 + 125:   true,
	((202<<8+99)<<8+254)<<8 + 230:  true,
	((202<<8+99)<<8+254)<<8 + 231:  true,
	((202<<8+99)<<8+254)<<8 + 232:  true,
	((211<<8+136)<<8+113)<<8 + 1:   true,
	((211<<8+137)<<8+130)<<8 + 101: true,
	((211<<8+138)<<8+102)<<8 + 198: true,
	((211<<8+138)<<8+34)<<8 + 204:  true,
	((211<<8+138)<<8+74)<<8 + 132:  true,
	((211<<8+139)<<8+136)<<8 + 73:  true,
	((211<<8+94)<<8+66)<<8 + 147:   true,
	((211<<8+98)<<8+70)<<8 + 195:   true,
	((211<<8+98)<<8+70)<<8 + 226:   true,
	((211<<8+98)<<8+70)<<8 + 227:   true,
	((211<<8+98)<<8+71)<<8 + 195:   true,
	((218<<8+28)<<8+144)<<8 + 36:   true,
	((218<<8+28)<<8+144)<<8 + 37:   true,
	((218<<8+28)<<8+144)<<8 + 38:   true,
	((218<<8+28)<<8+144)<<8 + 39:   true,
	((218<<8+28)<<8+144)<<8 + 40:   true,
	((218<<8+28)<<8+144)<<8 + 41:   true,
	((218<<8+28)<<8+144)<<8 + 42:   true,
	((218<<8+30)<<8+64)<<8 + 194:   true,
	((218<<8+68)<<8+250)<<8 + 117:  true,
	((218<<8+68)<<8+250)<<8 + 118:  true,
	((218<<8+68)<<8+250)<<8 + 119:  true,
	((218<<8+68)<<8+250)<<8 + 120:  true,
	((218<<8+68)<<8+250)<<8 + 121:  true,
	((218<<8+93)<<8+250)<<8 + 18:   true,
	((219<<8+146)<<8+13)<<8 + 36:   true,
	((220<<8+165)<<8+8)<<8 + 172:   true,
	((220<<8+165)<<8+8)<<8 + 174:   true,
	((220<<8+250)<<8+64)<<8 + 18:   true,
	((220<<8+250)<<8+64)<<8 + 19:   true,
	((220<<8+250)<<8+64)<<8 + 20:   true,
	((220<<8+250)<<8+64)<<8 + 21:   true,
	((220<<8+250)<<8+64)<<8 + 22:   true,
	((220<<8+250)<<8+64)<<8 + 225:  true,
	((220<<8+250)<<8+64)<<8 + 226:  true,
	((220<<8+250)<<8+64)<<8 + 227:  true,
	((220<<8+250)<<8+64)<<8 + 228:  true,
	((220<<8+250)<<8+64)<<8 + 23:   true,
	((220<<8+250)<<8+64)<<8 + 24:   true,
	((220<<8+250)<<8+64)<<8 + 25:   true,
	((220<<8+250)<<8+64)<<8 + 26:   true,
	((220<<8+250)<<8+64)<<8 + 27:   true,
	((220<<8+250)<<8+64)<<8 + 28:   true,
	((220<<8+250)<<8+64)<<8 + 29:   true,
	((220<<8+250)<<8+64)<<8 + 30:   true,
	((221<<8+179)<<8+46)<<8 + 190:  true,
	((221<<8+179)<<8+46)<<8 + 194:  true,
	((221<<8+192)<<8+153)<<8 + 41:  true,
	((221<<8+192)<<8+153)<<8 + 42:  true,
	((221<<8+192)<<8+153)<<8 + 43:  true,
	((221<<8+192)<<8+153)<<8 + 44:  true,
	((221<<8+192)<<8+153)<<8 + 45:  true,
	((221<<8+192)<<8+153)<<8 + 46:  true,
	((221<<8+192)<<8+153)<<8 + 49:  true,
	((221<<8+204)<<8+244)<<8 + 36:  true,
	((221<<8+204)<<8+244)<<8 + 37:  true,
	((221<<8+204)<<8+244)<<8 + 38:  true,
	((221<<8+204)<<8+244)<<8 + 39:  true,
	((221<<8+204)<<8+244)<<8 + 40:  true,
	((221<<8+204)<<8+244)<<8 + 41:  true,
	((221<<8+8)<<8+69)<<8 + 27:     true,
	((222<<8+221)<<8+5)<<8 + 204:   true,
	((222<<8+221)<<8+5)<<8 + 252:   true,
	((222<<8+221)<<8+5)<<8 + 253:   true,
	((223<<8+82)<<8+248)<<8 + 117:  true,
	((243<<8+185)<<8+187)<<8 + 3:   true,
	((243<<8+185)<<8+187)<<8 + 30:  true,
	((243<<8+185)<<8+187)<<8 + 39:  true,
	((249<<8+129)<<8+46)<<8 + 48:   true,
	((253<<8+157)<<8+14)<<8 + 165:  true,
	((255<<8+255)<<8+255)<<8 + 255: true,
	((42<<8+123)<<8+125)<<8 + 237:  true,
	((60<<8+19)<<8+29)<<8 + 21:     true,
	((60<<8+19)<<8+29)<<8 + 22:     true,
	((60<<8+19)<<8+29)<<8 + 23:     true,
	((60<<8+19)<<8+29)<<8 + 24:     true,
	((60<<8+19)<<8+29)<<8 + 25:     true,
	((60<<8+19)<<8+29)<<8 + 26:     true,
	((60<<8+19)<<8+29)<<8 + 27:     true,
	((60<<8+191)<<8+124)<<8 + 236:  true,
	((60<<8+191)<<8+124)<<8 + 252:  true,
	((61<<8+131)<<8+208)<<8 + 210:  true,
	((61<<8+131)<<8+208)<<8 + 211:  true,
	((61<<8+139)<<8+8)<<8 + 101:    true,
	((61<<8+139)<<8+8)<<8 + 102:    true,
	((61<<8+139)<<8+8)<<8 + 103:    true,
	((61<<8+139)<<8+8)<<8 + 104:    true,
	((61<<8+183)<<8+1)<<8 + 186:    true,
	((61<<8+191)<<8+206)<<8 + 4:    true,
	((61<<8+54)<<8+28)<<8 + 6:      true,
}
