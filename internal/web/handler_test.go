package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func servedTitle(t *testing.T) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/", nil)
	Handler().ServeHTTP(recorder, request)
	if recorder.Code != 200 {
		t.Fatalf("GET / status = %d", recorder.Code)
	}
	return recorder.Body.String()
}

func TestSetSiteTitleInjectsEscapedInitialTitle(t *testing.T) {
	SetSiteTitle(`纠缠 & <缘>`)
	body := servedTitle(t)
	if !strings.Contains(body, `<title>纠缠 &amp; &lt;缘&gt;</title>`) {
		t.Fatalf("served index does not contain escaped custom title")
	}
	if strings.Contains(body, siteTitlePlaceholder) {
		t.Fatalf("served index leaked title placeholder")
	}

	SetSiteTitle("")
	body = servedTitle(t)
	if !strings.Contains(body, `<title>`+defaultSiteTitle+`</title>`) {
		t.Fatalf("empty title did not restore default title")
	}
}
