package splicetraefikplugin_test

import (
	"context"
	"github.com/jfbramlett/splicetraefikplugin"
	"os"
	"testing"
)

func TestUserFromCookie(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		userUUID := "f2639c13-0427-9680-4a0b-0041b25b05cdfe9b556"
		userID := 2

		cm := splicetraefikplugin.NewSessionManager("_splice_web_session", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")
		usr, err := cm.UserFromHeader(context.Background(),
			`{"_splice_web_session":[{"name":"_splice_web_session","value":"TXNkY242VmtoU3RkYW43M1p3WDZhLzQrZ2lNanZnb1dOWmtiSDdNMEJwZUVTNERtOHdSSWJyR0lYM00wN2lxc2Z4T3ExZURYZWdDQy9iTk9xOUxiM1dXY0JSM3JGOG44WDZEREpUUjNtaGlONHpWV0I0d2dQWjVlSmU2dTRRTVN0OFptYzFjZlJoMVh3Ukw3YzZXWHRSOTZyTnNOU2JsSVY3aXhZdE16Z1UxNFNTTHo5bE5HQUxKVE9zeGFpclQ5VXRCdWRwNmFNMW4zQXFCTUo3SjdrL20xMHJXTSthblhlblA5c05ubEJNWT0tLW1Lek9XcmJPKy8wWElJeGpJalYrRUE9PQ%3D%3D--ae6274d00692c17335600ce02ad8828db1d5f390","domain":"splice.com","path":"/","http_only":true,"secure":true,"max_age":0,"expires":1646164766000}]}`)
		if err != nil {
			t.Fail()
		}

		if userUUID != usr.UUID {
			t.Error("user uuid's don't match")
		}
		if userID != usr.ID {
			t.Error("user id's don't match")
		}
	})

	t.Run("string cookie", func(t *testing.T) {
		userUUID := "f2639c13-0427-9680-4a0b-0041b25b05cdfe9b556"
		userID := 2

		cm := splicetraefikplugin.NewSessionManager("_splice_web_session", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")
		usr, err := cm.UserFromHeader(context.Background(),
			`_splice_web_session=TU10bmhxMFQ4M0dTYzNNMXBUTkpaL3IyTGR4bmkycTh5cklQMWU3WkJqaitIVnZORDY0dTR0M1FzYmhudW12OHhTUmtKbldib3Z1OWtDRjMrZ2UwQlV5NzdLVHk5OGQvK0sxREVXbFV1WFdMSkVmQ01rSjliWXZlUVM2NlplcENWNUsrK01DL3lqNjFrOHdiQzk1MHdpUWVFL2FuNHN0SjNqcWsyQUVOTXI2R1k0YXNMdm5qRG1PZk0xR1ZHOU1rd3BxOE8vbGlrcFJ0bG9VYlpKMXdmbUc4R0ZJL3VZYmIwcll5YTIrVkhXTT0tLXRUSHZ2WWpBNkcrUlpHK0pkbnRFRFE9PQ%3D%3D--92c0f8144340c45c35ee2005a6693475b84e70bf,Same Host`)
		if err != nil {
			t.Fail()
		}

		if userUUID != usr.UUID {
			t.Error("user uuid's don't match")
		}
		if userID != usr.ID {
			t.Error("user id's don't match")
		}
	})

	t.Run("success - cookie with extra info", func(t *testing.T) {
		userUUID := "f2639c13-0427-9680-4a0b-0041b25b05cdfe9b556"
		userID := 2

		cm := splicetraefikplugin.NewSessionManager("_splice_web_session", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")
		usr, err := cm.UserFromHeader(context.Background(),
			`{"_splice_web_session":[{"name":"_splice_web_session","value":"TXNkY242VmtoU3RkYW43M1p3WDZhLzQrZ2lNanZnb1dOWmtiSDdNMEJwZUVTNERtOHdSSWJyR0lYM00wN2lxc2Z4T3ExZURYZWdDQy9iTk9xOUxiM1dXY0JSM3JGOG44WDZEREpUUjNtaGlONHpWV0I0d2dQWjVlSmU2dTRRTVN0OFptYzFjZlJoMVh3Ukw3YzZXWHRSOTZyTnNOU2JsSVY3aXhZdE16Z1UxNFNTTHo5bE5HQUxKVE9zeGFpclQ5VXRCdWRwNmFNMW4zQXFCTUo3SjdrL20xMHJXTSthblhlblA5c05ubEJNWT0tLW1Lek9XcmJPKy8wWElJeGpJalYrRUE9PQ%3D%3D--ae6274d00692c17335600ce02ad8828db1d5f390","domain":"splice.com","path":"/","http_only":true,"secure":true,"max_age":0,"expires":1646164766000}]}; __cf_bm=KDNgePR0ZNg2sXAAz2RMs_8mUjQ0nvoVdrAMhZ3I5j8-1638539969-0-AZPwJmjhok6bu3Bco8bg1l7osEi5da72SxF/vxI8fAbpYXPJXKQJcaWQMkSldW3PiIPNx5s3tb0BjP/hfuR0CyzJh8e8LPcFQT2hiU8t/GbB`)
		if err != nil {
			t.Fail()
		}

		if userUUID != usr.UUID {
			t.Error("user uuid's don't match")
		}
		if userID != usr.ID {
			t.Error("user id's don't match")
		}
	})

	t.Run("invalid header return anonymous", func(t *testing.T) {
		cm := splicetraefikplugin.NewSessionManager("_splice_web_session", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")
		usr, err := cm.UserFromHeader(context.Background(), "_splice_web_session=bad_cookie")
		if err == nil {
			t.Fail()
		}

		if splicetraefikplugin.AnonymousUser.UUID != usr.UUID {
			t.Error("user uuid's don't match")
		}
		if splicetraefikplugin.AnonymousUser.ID != usr.ID {
			t.Error("user id's don't match")
		}

	})

	t.Run("missing cookie returns anonymous", func(t *testing.T) {
		cm := splicetraefikplugin.NewSessionManager("_splice_web_session", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")
		usr, err := cm.UserFromHeader(context.Background(), "_splice_cookie=some_other_value")
		if err == nil {
			t.Fail()
		}

		if splicetraefikplugin.AnonymousUser.UUID != usr.UUID {
			t.Error("user uuid's don't match")
		}
		if splicetraefikplugin.AnonymousUser.ID != usr.ID {
			t.Error("user id's don't match")
		}
	})

	t.Run("success - cfg from env", func(t *testing.T) {
		userUUID := "f2639c13-0427-9680-4a0b-0041b25b05cdfe9b556"
		userID := 2

		_ = os.Setenv("RAILS_COOKIE_NAME", "_splice_web_session")
		_ = os.Setenv("RAILS_SECRET", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")

		cm := splicetraefikplugin.NewSessionManager("", "")
		usr, err := cm.UserFromHeader(context.Background(),
			`{"_splice_web_session":[{"name":"_splice_web_session","value":"TXNkY242VmtoU3RkYW43M1p3WDZhLzQrZ2lNanZnb1dOWmtiSDdNMEJwZUVTNERtOHdSSWJyR0lYM00wN2lxc2Z4T3ExZURYZWdDQy9iTk9xOUxiM1dXY0JSM3JGOG44WDZEREpUUjNtaGlONHpWV0I0d2dQWjVlSmU2dTRRTVN0OFptYzFjZlJoMVh3Ukw3YzZXWHRSOTZyTnNOU2JsSVY3aXhZdE16Z1UxNFNTTHo5bE5HQUxKVE9zeGFpclQ5VXRCdWRwNmFNMW4zQXFCTUo3SjdrL20xMHJXTSthblhlblA5c05ubEJNWT0tLW1Lek9XcmJPKy8wWElJeGpJalYrRUE9PQ%3D%3D--ae6274d00692c17335600ce02ad8828db1d5f390","domain":"splice.com","path":"/","http_only":true,"secure":true,"max_age":0,"expires":1646164766000}]}`)
		if err != nil {
			t.Fail()
		}

		if userUUID != usr.UUID {
			t.Error("user uuid's don't match")
		}
		if userID != usr.ID {
			t.Error("user id's don't match")
		}
	})

}
