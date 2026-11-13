// Package provider: content resolution helpers for the windows_file resource.
//
// These helpers turn the six mutually exclusive content inputs (content,
// content_base64, content_wo, content_base64_wo, source, source_url) into the
// single base64 payload that winclient.FileClient.Set streams to the host, and
// compute the SHA-256 used for drift detection (decision D-2).
package provider

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Supported values of the `encoding` attribute.
const (
	fileEncodingUTF8       = "utf8"
	fileEncodingUTF8BOM    = "utf8bom"
	fileEncodingUTF16LE    = "utf16le"
	fileEncodingUTF16LEBOM = "utf16lebom"
	fileEncodingASCII      = "ascii"
	fileEncodingLatin1     = "latin1"
)

// fileEncodings is the schema enum for `encoding`.
var fileEncodings = []string{
	fileEncodingUTF8, fileEncodingUTF8BOM, fileEncodingUTF16LE,
	fileEncodingUTF16LEBOM, fileEncodingASCII, fileEncodingLatin1,
}

// fileDownloadTimeout bounds a provider-side source_url download, including
// retries and backoff. The apply path additionally derives its context from
// the resource `timeouts` (create/update, default fileDefaultTimeout), so
// the effective deadline is whichever expires first.
const fileDownloadTimeout = 10 * time.Minute

// fileDownloadAttempts is the total number of provider-side download tries:
// the initial attempt plus two retries with a short backoff (#325).
const fileDownloadAttempts = 3

// fileDownloadRetryBackoff is the pause between provider-side download
// attempts.
const fileDownloadRetryBackoff = time.Second

// fileUserAgent identifies provider-side source_url downloads. The provider
// version is not threaded through Configure (resources only receive the
// shared SSH client), so a constant token is used until version propagation
// exists; an explicit User-Agent entry in source_url_headers still wins.
const fileUserAgent = "terraform-provider-windows"

// encodeFileContent renders text content into the byte sequence to be written.
//
// The content is written verbatim: no line-ending translation happens here or
// on the host (EC-10). A HCL author on Linux who needs CRLF must put CRLF in
// the string.
func encodeFileContent(content, encoding string) ([]byte, error) {
	switch encoding {
	case "", fileEncodingUTF8:
		return []byte(content), nil

	case fileEncodingUTF8BOM:
		return append([]byte{0xEF, 0xBB, 0xBF}, []byte(content)...), nil

	case fileEncodingUTF16LE, fileEncodingUTF16LEBOM:
		units := utf16.Encode([]rune(content))
		out := make([]byte, 0, len(units)*2+2)
		if encoding == fileEncodingUTF16LEBOM {
			out = append(out, 0xFF, 0xFE)
		}
		var buf [2]byte
		for _, u := range units {
			binary.LittleEndian.PutUint16(buf[:], u)
			out = append(out, buf[0], buf[1])
		}
		return out, nil

	case fileEncodingASCII:
		for i, r := range content {
			if r > 0x7F {
				return nil, fmt.Errorf("content contains non-ASCII character %q at byte offset %d; use encoding = \"utf8\" instead", r, i)
			}
		}
		return []byte(content), nil

	case fileEncodingLatin1:
		if !utf8.ValidString(content) {
			return nil, fmt.Errorf("content is not valid UTF-8 and cannot be transcoded to latin1")
		}
		out := make([]byte, 0, len(content))
		for i, r := range content {
			if r > 0xFF {
				return nil, fmt.Errorf("content contains character %q at byte offset %d which has no latin1 representation", r, i)
			}
			out = append(out, byte(r)) //nolint:gosec // r <= 0xFF is checked above
		}
		return out, nil

	default:
		return nil, fmt.Errorf("unsupported encoding %q (expected one of %s)", encoding, strings.Join(fileEncodings, ", "))
	}
}

// sha256Hex returns the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// readLocalSource reads a file from the machine running Terraform (`source`).
// Failures surface at plan time rather than mid-apply.
func readLocalSource(path string) ([]byte, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the path is operator-supplied Terraform configuration by design
	if err != nil {
		return nil, fmt.Errorf("cannot read source file %q: %w", path, err)
	}
	return b, nil
}

// downloadSource fetches source_url provider-side (download_on = "terraform").
//
// The fetch runs under fileDownloadTimeout (further bounded by the resource
// timeouts the apply path puts on ctx) and retries transient failures —
// transport errors and HTTP 5xx — up to fileDownloadAttempts total tries.
// Permanent failures (invalid URL, HTTP 4xx, oversized body) fail fast.
func downloadSource(ctx context.Context, url string, headers map[string]string, insecureSkipVerify bool) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, fileDownloadTimeout)
	defer cancel()

	client := &http.Client{Timeout: fileDownloadTimeout}
	if insecureSkipVerify {
		client.Transport = &http.Transport{
			// #nosec G402 -- explicit, documented opt-out for internal CAs;
			// the provider raises a warning diagnostic when it is enabled.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	var lastErr error
	for attempt := 1; attempt <= fileDownloadAttempts; attempt++ {
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("invalid source_url %q: %w", url, err)
		}
		req.Header.Set("User-Agent", fileUserAgent)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("downloading %q failed: %w", url, err)
		} else {
			body, retryable, readErr := readDownloadBody(resp, url)
			_ = resp.Body.Close()
			if readErr == nil {
				return body, nil
			}
			if !retryable {
				return nil, readErr
			}
			lastErr = readErr
		}

		if attempt < fileDownloadAttempts {
			select {
			case <-reqCtx.Done():
				return nil, lastErr
			case <-time.After(fileDownloadRetryBackoff):
			}
		}
	}
	return nil, lastErr
}

// readDownloadBody consumes a download response. The retryable flag reports
// whether the caller should try again: HTTP 5xx only. Every other failure —
// 4xx, an unreadable body, or a body past the size cap — is permanent.
func readDownloadBody(resp *http.Response, url string) (body []byte, retryable bool, err error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err = fmt.Errorf("downloading %q returned HTTP %d", url, resp.StatusCode)
		return nil, resp.StatusCode >= 500, err
	}

	// Cap the read one byte above the limit so an oversized body is detected
	// without buffering the whole thing.
	body, err = io.ReadAll(io.LimitReader(resp.Body, winclient.FileMaxContentBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("reading body of %q failed: %w", url, err)
	}
	if int64(len(body)) > winclient.FileMaxContentBytes {
		return nil, false, fmt.Errorf("%q returned more than the %d byte limit of windows_file; consider download_on = \"target\"",
			url, winclient.FileMaxContentBytes)
	}
	return body, false, nil
}

// encodeBase64 is a thin wrapper kept for symmetry and testability.
func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// decodeBase64 validates and decodes a user-supplied base64 payload.
func decodeBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("value is not valid standard base64: %w", err)
	}
	return b, nil
}
