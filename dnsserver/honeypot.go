package dnsserver

import (
	"container/list"
	"crypto/tls"
	"github.com/miekg/dns"
	"log"
	"os"
	"sync"
	"time"
)

type Detective struct {
	safeDNS        string
	localDNS       string
	honeypotDNS    string
	cache          *DetectCache
	unsafeResolver *dns.Client
	safeResolver   *dns.Client
}

/*
	lru cache for pollution result, copy from tls pkg :P
 */
type DetectCache struct {
	sync.Mutex
	m        map[string]*list.Element
	q        *list.List
	capacity int
}

type pollutionCacheEntry struct {
	hostname string
	state    int
}

const HostnamePolluted = 1
const HostnameClean = 2

func (pc *DetectCache) Get(hostname string) (int, bool) {
	pc.Lock()
	defer pc.Unlock()

	if el, ok := pc.m[hostname]; ok {
		pc.q.MoveToFront(el)
		return el.Value.(*pollutionCacheEntry).state, true
	}
	return 0, false
}

func (pc *DetectCache) Put(hostname string, state int) {
	pc.Lock()
	defer pc.Unlock()

	if r, ok := pc.m[hostname]; ok {
		pc.q.MoveToFront(r)
		return
	}

	if pc.q.Len() < pc.capacity {
		entry := &pollutionCacheEntry{
			hostname: hostname,
			state:    state,
		}
		pc.m[hostname] = pc.q.PushFront(entry)
		return
	}

	el := pc.q.Back()
	entry := el.Value.(*pollutionCacheEntry)
	delete(pc.m, entry.hostname)
	entry.hostname = hostname
	entry.state = state
	pc.q.MoveToFront(el)
	pc.m[hostname] = el
}

func (pr *Detective) IsPolluted(hostname string, retry int) bool {
	if retry > 3 {
		// too many tries, force proxy
		return true
	}

	if state, ok := pr.cache.Get(hostname); ok {
		return state == HostnamePolluted
	} else {
		q := new(dns.Msg)
		fqdn := dns.Fqdn(hostname)

		q.SetQuestion(fqdn, dns.TypeA)

		if answer, _, err := pr.unsafeResolver.Exchange(q, pr.honeypotDNS); err != nil {
			return pr.IsPolluted(hostname, retry+1)
		} else if answer.Answer != nil {
			// GFW 如果抢答，判定为污染
			pr.cache.Put(hostname, HostnamePolluted)
			return true
		} else {
			// GFW 未抢答
			// 用本地 DNS 检查 hostname 解析结果中的 CNAME 记录, 需要递归判定是否 CNAME 被污染
			// 如果结果中的 CNAME 记录被污染，返回的结果仍然是不可用的
			if answer, _, err := pr.unsafeResolver.Exchange(q, pr.localDNS); err != nil {
				return pr.IsPolluted(hostname, retry+1)
			} else if answer != nil {
				for _, rr := range answer.Answer {
					if rr.Header().Rrtype == dns.TypeCNAME {
						cname := rr.(*dns.CNAME)
						if pr.IsPolluted(cname.Target, 0) {
							pr.cache.Put(hostname, HostnamePolluted)
							return true
						} else {
							pr.cache.Put(cname.Target, HostnameClean)
						}
					}
				}
			} else {
				// no error, no answer ，拒绝解析也是 GFW 一种污染手段，也有可能是偶然的网络错误，强制走代理
				pr.cache.Put(hostname, HostnamePolluted)
				return true
			}

			// 不是 CNAME，或者 CNAME 检查通过
			pr.cache.Put(hostname, HostnameClean)
		}
	}
	return false
}

func (pr *Detective) Resolve(oq *dns.Msg) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(oq.Question[0].Name, oq.Question[0].Qtype)

	var answer *dns.Msg

	if state, ok := pr.cache.Get(q.Question[0].Name); ok {
		log.Printf("cached detect result: %s = %d", oq.Question[0].Name, state)
		if state == HostnamePolluted {
			answer, _, _ = pr.safeResolver.Exchange(q, pr.safeDNS)
		} else {
			answer, _, _ = pr.unsafeResolver.Exchange(q, pr.localDNS)
		}
	} else {
		log.Printf("checking %s", q.Question[0].Name)
		pollutionDetect := pr.IsPolluted(q.Question[0].Name, 0)
		if pollutionDetect {
			answer, _, _ = pr.safeResolver.Exchange(q, pr.safeDNS)
		} else {
			answer, _, _ = pr.unsafeResolver.Exchange(q, pr.localDNS)
		}
	}

	return answer
}

func initDetective() *Detective {
	tlsResolver := new(dns.Client)
	tlsResolver.Net = "tcp4-tls"
	tlsResolver.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS12,
	}

	tlsResolver.DialTimeout = 5 * time.Second

	detective := Detective{
		unsafeResolver: new(dns.Client),
		safeResolver:   tlsResolver,
		cache: &DetectCache{
			m:        make(map[string]*list.Element),
			q:        list.New(),
			capacity: 1024,
		},
	}

	if dns := os.Getenv("TLS_DNS"); dns == "" {
		tlsResolver.TLSConfig.ServerName = "9.9.9.9:853"
		detective.safeDNS = "9.9.9.9:853"
	} else {
		tlsResolver.TLSConfig.ServerName = dns
		detective.safeDNS = dns
	}

	if dns := os.Getenv("LOCAL_DNS"); dns == "" {
		detective.localDNS = "119.29.29.29:53"
	} else {
		detective.localDNS = dns
	}

	if dns := os.Getenv("HONEYPOT_DNS"); dns == "" {
		detective.honeypotDNS = "198.11.138.248:53"
	} else {
		detective.honeypotDNS = dns
	}

	return &detective
}
