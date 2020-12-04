package ossobject

import (
	"io"
	"mime"
	"net/http"
	"path/filepath"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Interface guards
var (
	// _ caddy.Provisioner           = (*OSSObject)(nil)
	// _ caddy.Validator             = (*OSSObject)(nil)
	_ caddyhttp.MiddlewareHandler = (*OSSObject)(nil)
	_ caddyfile.Unmarshaler       = (*OSSObject)(nil)
)

func init() {
	caddy.RegisterModule(OSSObject{})
	httpcaddyfile.RegisterHandlerDirective("oss_object", parseCaddyfile)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// OSSObject implements an HTTP handler that
// provide content from aliyun oss
type OSSObject struct {
	Endpoint        string `json:"endpoint,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	Bucket          string `json:"bucket,omitempty"`
	ObjectKey       string `json:"object_key,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (OSSObject) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.oss_object",
		New: func() caddy.Module { return new(OSSObject) },
	}
}

// Provision implements caddy.Provisioner.
func (m *OSSObject) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	return nil
}

// Validate implements caddy.Validator.
// func (m OSSObject) Validate() error {
// if !hashAlgorithm(m.Algorithm).valid() {
// 	return fmt.Errorf("unsupported hash type '%s'", m.Algorithm)
// }
// if m.hasher == nil {
// 	// this will never happen
// 	return fmt.Errorf("hasher is null")
// }
// return nil
// }

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m OSSObject) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Method != http.MethodGet {
		return next.ServeHTTP(w, r)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	endpoint := repl.ReplaceAll(m.Endpoint, "")
	accessKeyID := repl.ReplaceAll(m.AccessKeyID, "")
	accessKeySecret := repl.ReplaceAll(m.AccessKeySecret, "")
	bucket := repl.ReplaceAll(m.Bucket, "")
	objectKey := repl.ReplaceAll(m.ObjectKey, "")

	ossClient, _ := oss.New(
		endpoint,
		accessKeyID,
		accessKeySecret,
	)

	bucketInstance, _ := ossClient.Bucket(bucket)

	// m.logger.Warn("request comes:",
	// 	zap.String("Endpoint", m.Endpoint),
	// 	zap.String("Bucket", m.Bucket),
	// 	zap.String("ObjectKey", m.ObjectKey),
	// )

	var options []oss.Option

	for headerK, headerV := range r.Header {
		// TODO: aliyun oss sdk only accept string header, so we can only pass one
		if len(headerV) >= 1 {
			options = append(options, oss.SetHeader(headerK, headerV[0]))
		}
	}

	result, err := bucketInstance.DoGetObject(&oss.GetObjectRequest{ObjectKey: objectKey}, options)
	if result == nil {
		m.logger.Error("error:", zap.Error(err))
		return next.ServeHTTP(w, r)
	}
	defer result.Response.Close()

	// reqHeaderJSON, _ := json.Marshal(r.Header)
	// resHeaderJSON, _ := json.Marshal(result.Response.Headers)
	// m.logger.Warn("result:",
	// 	zap.String("Request", string(reqHeaderJSON)),
	// 	zap.String("Response", string(resHeaderJSON)),
	// 	zap.Int("StatusCode", result.Response.StatusCode),
	// )

	copyHeader(w.Header(), result.Response.Headers)
	mtyp := mime.TypeByExtension(filepath.Ext(r.URL.Path))
	if mtyp == "" {
		// do not allow Go to sniff the content-type; see
		// https://www.youtube.com/watch?v=8t8JYpt0egE
		// TODO: If we want a Content-Type, consider writing a default of application/octet-stream - this is secure but violates spec
		w.Header()["Content-Type"] = nil
	} else {
		w.Header().Set("Content-Type", mtyp)
	}

	w.WriteHeader(result.Response.StatusCode)

	io.Copy(w, result.Response)

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//    oss_object {
//			endpoint oss-cn-shanghai.aliyuncs.com
//			access_key_id IWILLNOTTELLU
//			access_key_secret IWILLNOTTELLU
//			bucket test
//			object_key test/index.html
//    }
// TODO: add validator
func (m *OSSObject) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()

		if len(args) != 0 {
			return d.ArgErr()
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "endpoint":
				endpoint := d.RemainingArgs()
				if len(endpoint) == 1 {
					m.Endpoint = endpoint[0]
				} else {
					return d.ArgErr()
				}
			case "access_key_id":
				accessKeyID := d.RemainingArgs()
				if len(accessKeyID) == 1 {
					m.AccessKeyID = accessKeyID[0]
				} else {
					return d.ArgErr()
				}
			case "access_key_secret":
				accessKeySecret := d.RemainingArgs()
				if len(accessKeySecret) == 1 {
					m.AccessKeySecret = accessKeySecret[0]
				} else {
					return d.ArgErr()
				}
			case "bucket":
				bucket := d.RemainingArgs()
				if len(bucket) == 1 {
					m.Bucket = bucket[0]
				} else {
					return d.ArgErr()
				}
			case "object_key":
				objectKey := d.RemainingArgs()
				if len(objectKey) == 1 {
					m.ObjectKey = objectKey[0]
				} else {
					return d.ArgErr()
				}
			default:
				return d.Errf("unknown subdirective '%s'", d.Val())
			}
		}
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m OSSObject
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}
