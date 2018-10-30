package dnsserver

import (
	"crypto/tls"
	"github.com/labstack/gommon/log"
	"github.com/miekg/dns"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var tlsDNS string
var localDNS string
var dnsServerOnce sync.Once

func StartDNSServer() {
	dnsServerOnce.Do(func() {
		tlsDNS = os.Getenv("TLS_DNS")
		if tlsDNS == "" {
			tlsDNS = "q9dns.nowall.online:853"
		}
		log.Printf("TLS_DNS %s", tlsDNS)
		localDNS = os.Getenv("LOCAL_DNS")
		if localDNS == "" {
			localDNS = "192.29.29.29:53"
		}
		log.Printf("LOCAL_DNS %s", localDNS)

		initHoneyPotResolver()
		go cacheSupervisor()
	})

	server := dns.Server{Addr: ":1053", Net: "udp"}
	tlsClient := new(dns.Client)

	tlsClient.Net = "tcp4-tls"
	safeDNS := strings.Split(tlsDNS, ":")

	tlsClient.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}
	tlsClient.DialTimeout = 30 * time.Second

	var safeDNSIP string

	// only hostname can be used as tls session cache key
	if len(safeDNS) > 1 {
		tlsClient.TLSConfig.ServerName = safeDNS[0]
		if safeDNSIP_, err := net.LookupIP(safeDNS[0]); err != nil {
			safeDNSIP = "9.9.9.9:853"	// fallback to quad9
		} else {
			safeDNSIP = net.JoinHostPort(safeDNSIP_[0].String(), safeDNS[1])
		}
	}

	localClient := new(dns.Client)

	dns.HandleFunc(".", func(writer dns.ResponseWriter, msg *dns.Msg) {
		fqdn := msg.Question[0].Name
		var answer *dns.Msg
		var rtt time.Duration
		var err error

		//log.Printf("querying %s", fqdn)

		if polluted := IsHostnamePolluted(fqdn); polluted {
			// query through dns-over-tls
			answer, rtt, err = tlsClient.Exchange(msg, safeDNSIP)
			log.Printf("%s polluted, resolver: %s", fqdn, safeDNSIP)
		} else {
			answer, rtt, err = localClient.Exchange(msg, localDNS)
			if answer == nil || err != nil {
				log.Printf("%s is clean, resolver %s", fqdn, safeDNSIP)
				answer, rtt, err = tlsClient.Exchange(msg, safeDNSIP)
			} else {
				log.Printf("%s is clean, resolver: %s", fqdn, localDNS)
			}
		}

		//fmt.Printf("[[[[answer]]]]: %+v\n[[[[rt]]]]: %d\n", answer, rtt)
		_ = rtt

		if err == nil && answer != nil {
			answer.SetReply(msg)
			writer.WriteMsg(answer)
		} else {
			answer = new(dns.Msg)
			answer.SetReply(msg)
			answer.SetRcode(msg, dns.RcodeNameError)
			writer.WriteMsg(answer)
		}
	})

	server.ListenAndServe()
}
