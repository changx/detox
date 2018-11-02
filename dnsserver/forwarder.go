package dnsserver

import (
	"github.com/miekg/dns"
	"sync"
	"time"
)

var dnsServerOnce sync.Once
var detective *Detective

func StartDNSServer() {
	dnsServerOnce.Do(func() {
		detective = initDetective()
	})

	server := dns.Server{Addr: ":1053", Net: "udp"}

	dns.HandleFunc(".", func(writer dns.ResponseWriter, msg *dns.Msg) {
		var answer *dns.Msg
		var rtt time.Duration
		var err error

		//log.Printf("querying %s", fqdn)

		//fmt.Printf("[[[[answer]]]]: %+v\n[[[[rt]]]]: %d\n", answer, rtt)

		answer = detective.Resolve(msg)

		//log.Printf("%+v", answer)

		_ = rtt

		if err == nil && answer != nil {
			//log.Printf("%+v", answer)
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
