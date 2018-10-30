package dnsserver

import (
	"encoding/json"
	"github.com/labstack/gommon/log"
	"github.com/miekg/dns"
	"os"
	"sync"
	"time"
)

var honeypotOnce = sync.Once{}
var honeypotResolver *dns.Client
var honeypotDNS string

var cacheOnce = sync.Once{}
var nameCache = sync.Map{}
var defaultCacheTTL = 300 * time.Second

type hostnameCacheItem struct {
	State  int   `json:"state"`
	Expiry int64 `json:"expiry"`
}

const (
	kHostNameClean    = 1
	kHostNamePolluted = 2
)

func addNameToCache(name string, state int) {
	now := time.Now().Add(time.Hour).Unix()
	nameCache.Store(name, hostnameCacheItem{
		State: state,
		Expiry: now,
	})
}

func initHoneyPotResolver() {
	cacheOnce.Do(func() {
		honeypotDNS = os.Getenv("HONEYPOT_DNS")
		if honeypotDNS == "" {
			honeypotDNS = "198.11.138.248:53"
		}
		localDNS = os.Getenv("LOCAL_DNS")
		if localDNS == "" {
			localDNS = "119.29.29.29:53"
		}
		honeypotResolver = new(dns.Client)

		log.Printf("HONEYPOT_DNS %s as GFW DNS honey pot", honeypotDNS)
		log.Printf("LOCAL_DNS %s as local resolver", localDNS)

		cacheFile, _ := os.Open("/detox/cache.json")
		if cacheFile != nil {
			defer cacheFile.Close()
			cacheMap := make(map[string]hostnameCacheItem)
			json.NewDecoder(cacheFile).Decode(&cacheMap)

			if len(cacheMap) > 0 {
				for key, val := range cacheMap {
					nameCache.Store(key, val)
				}
			}
		}
	})
}

func cacheSupervisor() {
	expiredNames := make([]string, 0)
	for {
		log.Print("clearning expired cache")

		cacheMap := make(map[string]interface{})
		now := time.Now().Unix()
		expiredNames = expiredNames[:0]
		nameCache.Range(func(key, value interface{}) bool {
			cacheItem := value.(hostnameCacheItem)
			if cacheItem.Expiry >= now {
				cacheMap[key.(string)] = cacheItem
			} else {
				expiredNames = append(expiredNames, key.(string))
			}
			return true
		})

		for _, name := range expiredNames {
			nameCache.Delete(name)
		}

		// serialize to cache file
		if cacheMap != nil {
			if cacheFile, err := os.Create("/detox/cache.json"); err == nil {
				if cache, err := json.Marshal(cacheMap); cache != nil {
					cacheFile.Write(cache)
				} else {
					log.Printf("cache serialization failed", err.Error())
				}
				cacheFile.Close()
			} else {
				log.Print("unable create cache file")
			}
		}
		log.Print("validation done")
		time.Sleep(defaultCacheTTL)
	}
}

func IsHostnamePolluted(hostname string) bool {

	if isCachedHostname(hostname) {
		return cachedResult(hostname)
	}

	return validateHostname(hostname, 0)
}

func validateHostname(hostname string, try int) bool {

	if try > 5 {
		addNameToCache(hostname, kHostNamePolluted)
		return cachedResult(hostname)
	}

	if try > 0 {
		log.Printf("retrying %s, %d times", hostname, try)
	}

	targetHostname := hostname
	//if hostname == "google.com" {
	//	targetHostname = "www.google.com"
	//}

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(targetHostname), dns.TypeA)
	answer, _, err := honeypotResolver.Exchange(q, honeypotDNS)
	if err != nil {
		log.Printf("err: %s", err.Error())
		return validateHostname(hostname, try+1)
	}

	if answer.Answer != nil {
		addNameToCache(hostname, kHostNamePolluted)
	} else {
		answer, _, err = honeypotResolver.Exchange(q, localDNS)
		if answer == nil || err != nil {
			return validateHostname(hostname, try+1)
		}

		for _, rr := range answer.Answer {
			if rr.Header().Rrtype == dns.TypeCNAME {
				cname := rr.(*dns.CNAME)
				log.Debugf("[[[[cname]]]]: %+v\n", cname)
				if IsHostnamePolluted(cname.Target) {
					log.Debugf("cname %s polluted", cname.Target)
					addNameToCache(cname.Target, kHostNamePolluted)
					addNameToCache(hostname, kHostNamePolluted)
					return cachedResult(hostname)
				} else {
					addNameToCache(cname.Target, kHostNameClean)
					// cname target is clean, continue next target
				}
			}
		}

		addNameToCache(hostname, kHostNameClean)
	}
	return cachedResult(hostname)
}

func cachedResult(hostname string) bool {
	if result, ok := nameCache.Load(hostname); ok {
		cacheItem := result.(hostnameCacheItem)
		switch cacheItem.State {
		case kHostNameClean:
			return false
		default:
			return true
		}
	}
	// ya, force result as polluted
	return true
}

func isCachedHostname(hostname string) bool {
	_, ok := nameCache.Load(hostname)
	return ok
}
