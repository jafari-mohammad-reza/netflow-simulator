package pkg

import (
	"fmt"
	"time"
)

var countries = []string{"Afghanistan", "Albania",
	"Algeria",
	"Andorra",
	"Angola",
	"Antigua & Deps",
	"Argentina",
	"Armenia",
	"Australia",
	"Austria",
	"Azerbaijan",
	"Bahamas",
	"Bahrain",
	"Bangladesh",
	"Barbados",
	"Belarus",
	"Belgium",
	"Belize",
	"Benin",
	"Bhutan",
	"Bolivia",
	"Bosnia Herzegovina",
	"Botswana",
	"Brazil",
	"Brunei",
	"Bulgaria",
	"Burkina",
	"Burundi",
	"Cambodia",
	"Cameroon",
	"Canada",
	"Cape Verde",
	"Central African Rep",
	"Chad",
	"Chile",
	"China",
	"Colombia",
	"Comoros",
	"Congo",
	"Congo {Democratic Rep}",
	"Costa Rica",
	"Croatia",
	"Cuba",
	"Cyprus",
	"Czech Republic",
	"Denmark",
	"Djibouti",
	"Dominica",
	"Dominican Republic",
	"East Timor",
	"Ecuador",
	"Egypt",
	"El Salvador",
	"Equatorial Guinea",
	"Eritrea",
	"Estonia",
	"Ethiopia",
	"Fiji",
	"Finland",
	"France",
	"Gabon",
	"Gambia",
	"Georgia",
	"Germany",
	"Ghana",
	"Greece",
	"Grenada",
	"Guatemala",
	"Guinea",
	"Guinea-Bissau",
	"Guyana",
	"Haiti",
	"Honduras",
	"Hungary",
	"Iceland",
	"India",
	"Indonesia",
	"Iran",
	"Iraq",
	"Ireland",
	"Israel",
	"Italy",
	"Ivory Coast",
	"Jamaica",
	"Japan",
	"Jordan",
	"Kazakhstan",
	"Kenya",
	"Kiribati",
	"Korea North",
	"Korea South",
	"Kosovo",
	"Kuwait",
	"Kyrgyzstan",
	"Laos",
	"Latvia",
	"Lebanon",
	"Lesotho",
	"Liberia",
	"Libya",
	"Liechtenstein",
	"Lithuania",
	"Luxembourg",
	"Macedonia",
	"Madagascar",
	"Malawi",
	"Malaysia",
	"Maldives",
	"Mali",
	"Malta",
	"Marshall Islands",
	"Mauritania",
	"Mauritius",
	"Mexico",
	"Micronesia",
	"Moldova",
	"Monaco",
	"Mongolia",
	"Montenegro",
	"Morocco",
	"Mozambique",
	"Myanmar",
	"Namibia",
	"Nauru",
	"Nepal",
	"Netherlands",
	"New Zealand",
	"Nicaragua",
	"Niger",
	"Nigeria",
	"Norway",
	"Oman",
	"Pakistan",
	"Palau",
	"Panama",
	"Papua New Guinea",
	"Paraguay",
	"Peru",
	"Philippines",
	"Poland",
	"Portugal",
	"Qatar",
	"Romania",
	"Russian Federation",
	"Rwanda",
	"St Kitts & Nevis",
	"St Lucia",
	"Saint Vincent & the Grenadines",
	"Samoa",
	"San Marino",
	"Sao Tome & Principe",
	"Saudi Arabia",
	"Senegal",
	"Serbia",
	"Seychelles",
	"Sierra Leone",
	"Singapore",
	"Slovakia",
	"Slovenia",
	"Solomon Islands",
	"Somalia",
	"South Africa",
	"South Sudan",
	"Spain",
	"Sri Lanka",
	"Sudan",
	"Suriname",
	"Swaziland",
	"Sweden",
	"Switzerland",
	"Syria",
	"Taiwan",
	"Tajikistan",
	"Tanzania",
	"Thailand",
	"Togo",
	"Tonga",
	"Trinidad & Tobago",
	"Tunisia",
	"Turkey",
	"Turkmenistan",
	"Tuvalu",
	"Uganda",
	"Ukraine",
	"United Arab Emirates",
	"United Kingdom",
	"United States",
	"Uruguay",
	"Uzbekistan",
	"Vanuatu",
	"Vatican City",
	"Venezuela",
	"Vietnam",
	"Yemen",
	"Zambia",
	"Zimbabwe",
}
var countriesMap = map[int64]string{}

func init() {
	for i, country := range countries {
		countriesMap[int64(i)] = country
	}
}
func GetCountryIndex(name string) int64 {
	for i, country := range countries {
		if country == name {
			return int64(i)
		}
	}
	return -1
}
func AddCountry(name string) int64 {
	newIndex := int64(len(countries))
	countries = append(countries, name)
	countriesMap[newIndex] = name
	return newIndex
}

var ispMap = map[int64]string{
	0: "ISP-A",
	1: "ISP-B",
	2: "ISP-C",
	3: "ISP-D",
	4: "ISP-E",
	5: "ISP-F",
	6: "ISP-G",
	7: "ISP-H",
	8: "ISP-I",
	9: "ISP-J",
}
var protocolsMap = []Protocol{
	ProtocolTCP,
	ProtocolUDP,
	ProtocolICMP,
}

func GetRandCountry() string {
	n := time.Now().UnixNano() % int64(len(countries))
	return countries[n]
}
func GetRandISP() string {
	n := time.Now().UnixNano() % int64(len(ispMap))
	return ispMap[n]
}
func GetIspIndex(isp string) int64 {
	for i, name := range ispMap {
		if name == isp {
			return i
		}
	}
	return -1
}
func AddIsp(isp string) int64 {
	newIndex := int64(len(ispMap))
	ispMap[newIndex] = isp
	return newIndex
}
func GetRandProtocol() Protocol {
	n := time.Now().UnixNano() % int64(len(protocolsMap))
	return protocolsMap[n]
}
func GetRandDirection() string {
	n := time.Now().UnixNano() % 2
	if n == 0 {
		return "IN"
	}
	return "OUT"
}

func GetRandIP() string {
	n1 := time.Now().UnixNano() % 128
	n2 := time.Now().UnixNano() % 256
	n3 := time.Now().UnixNano() % 256
	n4 := time.Now().UnixNano() % 256
	return fmt.Sprintf("%d.%d.%d.%d", n1, n2, n3, n4)
}
