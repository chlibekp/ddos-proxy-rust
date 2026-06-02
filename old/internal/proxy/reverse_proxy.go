package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gregjones/httpcache"
	"github.com/gregjones/httpcache/diskcache"
	"github.com/hegy/ddos-proxy/internal/config"
)

// jsSnippet is the mitigation-detection script injected into HTML responses.
// Declared as []byte to avoid repeated string→[]byte conversion.
var jsSnippet = []byte(`<script>(function(){var r=function(){window.location.reload()};var c=function(h){if(h==='challenge')r()};var f=window.fetch;if(f){window.fetch=function(){return f.apply(this,arguments).then(function(res){if(res&&res.headers&&res.headers.get){c(res.headers.get('X-Mitigation'))}return res})}}var x=XMLHttpRequest.prototype;var o=x.open;x.open=function(){this.addEventListener('load',function(){if(this.getResponseHeader){c(this.getResponseHeader('X-Mitigation'))}});return o.apply(this,arguments)};if(window.fetch){document.addEventListener('error',function(e){var t=e.target;if(t&&t.tagName&&(t.src||t.href)){var g=t.tagName;if(g==='IMG'||g==='SCRIPT'||g==='LINK'||g==='IFRAME'||g==='VIDEO'||g==='AUDIO'){var u=t.src||t.href;if(u&&u.indexOf('data:')!==0){window.fetch(u,{method:'HEAD'}).catch(function(){})}}}},true)}})();</script>`)

var headTag = []byte("<head>")
var bodyTag = []byte("<body>")

// bodyBufPool pools buffers used for reading HTML response bodies during JS injection.
var bodyBufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// NormalizingTransport wraps an http.RoundTripper to fix malformed Cache-Control headers
type NormalizingTransport struct {
	Transport http.RoundTripper
}

func (n *NormalizingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := n.Transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// The httpcache library uses headers.Get("Cache-Control"), which only returns the FIRST
	// Cache-Control header if there are multiple. We need to merge them into one.
	if ccHeaders, ok := resp.Header["Cache-Control"]; ok && len(ccHeaders) > 0 {
		merged := strings.Join(ccHeaders, ", ")

		// Some backends return malformed headers like "max-age 86400" instead of "max-age=86400"
		// The httpcache library expects the strict RFC format with equals signs.
		re := regexp.MustCompile(`(max-age|s-maxage)\s+(\d+)`)
		merged = re.ReplaceAllString(merged, "$1=$2")

		resp.Header.Set("Cache-Control", merged)
	}

	return resp, nil
}

// WebSocketAwareTransport bypasses the cache transport for WebSocket upgrade requests
type WebSocketAwareTransport struct {
	DefaultTransport http.RoundTripper
	CacheTransport   http.RoundTripper
}

func (t *WebSocketAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if isWebSocketUpgrade(req) {
		return t.DefaultTransport.RoundTrip(req)
	}
	if t.CacheTransport != nil {
		return t.CacheTransport.RoundTrip(req)
	}
	return t.DefaultTransport.RoundTrip(req)
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") &&
		strings.ToLower(req.Header.Get("Upgrade")) == "websocket"
}

// New creates a new reverse proxy handler for the given target URL.
// It includes logic for header manipulation and JS injection for mitigation checks.
func New(target *url.URL, cfg *config.Config) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	baseTransport := &http.Transport{
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if cfg.CacheEnabled {
		cacheDir := "/tmp/ddos-mitigator-cache"
		slog.Info("Enabling disk cache", "dir", cacheDir)
		cache := diskcache.New(cacheDir)

		normalizedTransport := &NormalizingTransport{
			Transport: baseTransport,
		}

		cacheTransport := httpcache.NewTransport(cache)
		cacheTransport.Transport = normalizedTransport

		proxy.Transport = &WebSocketAwareTransport{
			DefaultTransport: baseTransport,
			CacheTransport:   cacheTransport,
		}
	} else {
		proxy.Transport = &WebSocketAwareTransport{
			DefaultTransport: baseTransport,
			CacheTransport:   nil,
		}
	}

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalHost := req.Host
		originalDirector(req)
		req.Host = originalHost

		// We only need to disable Accept-Encoding if we plan to inspect/modify the body
		// For Next.js image optimization (and many other binary formats), we should NOT strip Accept-Encoding
		// The proxy.ModifyResponse only modifies text/html, so we only need to strip Accept-Encoding for HTML requests
		if strings.Contains(req.Header.Get("Accept"), "text/html") {
			req.Header.Del("Accept-Encoding")
		}

		// Set X-Forwarded-Host if not present
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", originalHost)
		}
		// Set X-Forwarded-Proto if not present
		if req.Header.Get("X-Forwarded-Proto") == "" {
			scheme := "http"
			if req.TLS != nil {
				scheme = "https"
			}
			req.Header.Set("X-Forwarded-Proto", scheme)
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// Do not modify WebSocket upgrade responses
		if resp.StatusCode == http.StatusSwitchingProtocols {
			return nil
		}

		// Add Via header for clean traffic identification
		resp.Header.Set("Via", "ddos-proxy")
		resp.Header.Del("server")
		resp.Header.Set("server", "ddos-proxy")

		// Handle cache status header
		if cfg.CacheEnabled {
			if resp.Header.Get("X-From-Cache") == "1" {
				resp.Header.Set("X-Ddos-Proxy-Cache", "HIT")
				resp.Header.Del("X-From-Cache")
			} else {
				// If it's not from cache, but Cache-Control allows caching, it's a MISS.
				// Otherwise, it's DYNAMIC.
				cc := resp.Header.Get("Cache-Control")
				if cc != "" && !strings.Contains(cc, "no-cache") && !strings.Contains(cc, "no-store") && !strings.Contains(cc, "private") {
					resp.Header.Set("X-Ddos-Proxy-Cache", "MISS")
				} else {
					resp.Header.Set("X-Ddos-Proxy-Cache", "DYNAMIC")
				}
			}
		} else {
			resp.Header.Set("X-Ddos-Proxy-Cache", "DYNAMIC")
		}

		// Inject mitigation-detection JS into HTML responses.
		contentType := resp.Header.Get("Content-Type")
		if strings.HasPrefix(contentType, "text/html") {
			ce := resp.Header.Get("Content-Encoding")
			if ce != "" && ce != "identity" && ce != "gzip" {
				// Unsupported encoding — skip injection to avoid corrupting body.
				return nil
			}

			buf := bodyBufPool.Get().(*bytes.Buffer)
			buf.Reset()

			var readErr error
			if ce == "gzip" {
				gr, err := gzip.NewReader(resp.Body)
				if err == nil {
					_, readErr = io.Copy(buf, gr)
					gr.Close()
				} else {
					_, readErr = io.Copy(buf, resp.Body)
				}
			} else {
				_, readErr = io.Copy(buf, resp.Body)
			}
			resp.Body.Close()
			if readErr != nil {
				bodyBufPool.Put(buf)
				return readErr
			}

			body := buf.Bytes()
			out := make([]byte, 0, len(body)+len(jsSnippet))
			if idx := bytes.Index(body, headTag); idx >= 0 {
				out = append(out, body[:idx+len(headTag)]...)
				out = append(out, jsSnippet...)
				out = append(out, body[idx+len(headTag):]...)
			} else if idx := bytes.Index(body, bodyTag); idx >= 0 {
				out = append(out, body[:idx+len(bodyTag)]...)
				out = append(out, jsSnippet...)
				out = append(out, body[idx+len(bodyTag):]...)
			} else {
				out = append(out, jsSnippet...)
				out = append(out, body...)
			}

			bodyBufPool.Put(buf)

			if ce == "gzip" {
				resp.Header.Del("Content-Encoding")
			}

			resp.Body = io.NopCloser(bytes.NewReader(out))
			resp.ContentLength = int64(len(out))
			resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
		}

		location := resp.Header.Get("Location")
		if location == "" {
			return nil
		}

		locURL, err := url.Parse(location)
		if err != nil {
			return nil
		}

		// If the redirect location host matches the backend target host,
		// rewrite it to the original request host.
		if locURL.Host == target.Host {
			locURL.Host = resp.Request.Host

			// Attempt to preserve the scheme from X-Forwarded-Proto
			scheme := resp.Request.Header.Get("X-Forwarded-Proto")
			if scheme == "" {
				if resp.Request.TLS != nil {
					scheme = "https"
				} else {
					scheme = "http"
				}
			}
			locURL.Scheme = scheme

			resp.Header.Set("Location", locURL.String())
		}
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("Proxy error", "error", err, "path", r.URL.Path)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	return proxy
}
