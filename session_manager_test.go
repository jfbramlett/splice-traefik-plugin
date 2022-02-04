package splicetraefikplugin_test

import (
	"context"
	"os"
	"testing"

	"github.com/jfbramlett/splicetraefikplugin"
)

func TestUserFromCookie(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		userUUID := "f2639c13-0427-9680-4a0b-0041b25b05cdfe9b556"
		userID := 2

		_ = os.Setenv("RAILS_COOKIE_NAME", "_splice_web_session")
		_ = os.Setenv("RAILS_SECRET", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")

		cm := splicetraefikplugin.NewSessionManager()
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

		_ = os.Setenv("RAILS_COOKIE_NAME", "_splice_web_session")
		_ = os.Setenv("RAILS_SECRET", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")

		cm := splicetraefikplugin.NewSessionManager()
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

		_ = os.Setenv("RAILS_COOKIE_NAME", "_splice_web_session")
		_ = os.Setenv("RAILS_SECRET", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")

		cm := splicetraefikplugin.NewSessionManager()
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
		_ = os.Setenv("RAILS_COOKIE_NAME", "_splice_web_session")
		_ = os.Setenv("RAILS_SECRET", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")

		cm := splicetraefikplugin.NewSessionManager()
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
		_ = os.Setenv("RAILS_COOKIE_NAME", "_splice_web_session")
		_ = os.Setenv("RAILS_SECRET", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")

		cm := splicetraefikplugin.NewSessionManager()
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

		cm := splicetraefikplugin.NewSessionManager()
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

	t.Run("k6 example", func(t *testing.T) {
		t.Skip("bad RAILS_SECRET")
		userUUID := "f2639c13-0427-9680-4a0b-0041b25b05cdfe9b556"
		userID := 2

		_ = os.Setenv("RAILS_COOKIE_NAME", "_splice_staging_session")
		_ = os.Setenv("RAILS_SECRET", "f7b5763636f4c1f3ff4bd444eacccca295d87b990cc104124017ad70550edcfd22b8e89465338254e0b608592a9aac29025440bfd9ce53579835ba06a86f85f9")

		cm := splicetraefikplugin.NewSessionManager()

		usr, err := cm.UserFromHeader(context.Background(),
			`{"_splice_staging_session":[{"name":"_splice_staging_session","value":"ZjZIVjlGMWl5MmlaV0dVTmhiVGZqMHI5L3VDZXpBRDZ0ZmxiekcvdldISzN6SUdud0hreTVYcDZFMkd3VXZRMmRpWWlnSE1nTnFPK1hkVTd4SzhCajQ2c2V0cHo4Z0EwTkZXZEtpRm1RL1lNWEVqL1MwSjh5MTh3WHkzT2RqMlFFNGIya3FuREZ6ZmIzQ044TGQvSUVXeW00M3JhMFhGcGo0dXd3Tm9qUGFVcm1uQ0ZkM2NXM0ovTmt2S0hiSm5Yc2oyOCtwWUZjOW9DVEczd3VCbHM5bjdWZUIrRTZFWjNkMTVWTURaU29IND0tLWsyWGFLZEVQdkNNM09tRFN3U1dSbXc9PQ%3D%3D--3ca983960403001056b6164c4e2cf6d538cc2f6a","domain":"splice.com","path":"/","http_only":true,"secure":true,"max_age":0,"expires":1651613232000}],"XSRF-TOKEN":[{"name":"XSRF-TOKEN","value":"7hTdNXC64wlrlrniKaReeeuPHog:1643923632823","domain":"splice.com","path":"/","http_only":false,"secure":true,"max_age":0,"expires":1644010032000}]}; __cf_bm=IMJaY1ODLTQiCiho5MLd0yAsggfy4ZrrWu7imlKIxws-1643923735-0-AVkHKsq42HzKs1q5IsPn9legL0ib5+6uuMCT11zBbf5DI0+RWa37/dDFbb7tSitG71buu3bjZS69KjgHgkNmS+kB2ymZL/JoaYPkUR/HW4Kz`)
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
