package encrypt

import (
	"regexp"
	"strings"
	"testing"
)

// TestPathMatchingWithoutLeadingSlash 测试没有前导 / 的路径匹配
func TestPathMatchingWithoutLeadingSlash(t *testing.T) {
	// 模拟 wildcardToRegex 函数
	wildcardToRegex := func(raw string) string {
		a := "__AST__"
		q := "__QST__"
		tmp := strings.ReplaceAll(raw, "*", a)
		tmp = strings.ReplaceAll(tmp, "?", q)
		tmp = regexp.QuoteMeta(tmp)
		tmp = strings.ReplaceAll(tmp, a, ".*")
		tmp = strings.ReplaceAll(tmp, q, ".")
		return tmp
	}

	testCases := []struct {
		configPath string   // 配置的加密路径
		testPaths  []string // 要测试的文件路径
		shouldMatch bool
	}{
		{
			// 有前导 / 的配置
			configPath: "/移动云盘156/encrypt/*",
			testPaths: []string{
				"/移动云盘156/encrypt/test.mp4",
				"/移动云盘156/encrypt/87kdQg0Y5VOWIUjeU~Xtcg435V+YO0--y.mp4",
			},
			shouldMatch: true,
		},
		{
			// 没有前导 / 的配置（用户的实际情况）
			configPath: "移动云盘156/encrypt/*",
			testPaths: []string{
				"/移动云盘156/encrypt/test.mp4",
				"/移动云盘156/encrypt/87kdQg0Y5VOWIUjeU~Xtcg435V+YO0--y.mp4",
			},
			shouldMatch: true,
		},
		{
			// 没有前导 / 的配置（末尾是 / 而不是 /*）
			configPath: "移动云盘156/encrypt/",
			testPaths: []string{
				"/移动云盘156/encrypt/test.mp4",
				"/移动云盘156/encrypt/87kdQg0Y5VOWIUjeU~Xtcg435V+YO0--y.mp4",
			},
			shouldMatch: true,
		},
		{
			// 有前导 / 的联通云盘
			configPath: "/156联通云盘/encrypt/*",
			testPaths: []string{
				"/156联通云盘/encrypt/test.mp4",
			},
			shouldMatch: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.configPath, func(t *testing.T) {
			raw := tc.configPath
			var pattern string

			// 复制 proxy.go 中的逻辑
			if strings.HasSuffix(raw, "/*") {
				base := strings.TrimSuffix(raw, "/*")
				converted := wildcardToRegex(base)
				if strings.HasPrefix(base, "/") {
					pattern = "^" + converted + "(/.*)?$"
				} else {
					pattern = "^/?" + converted + "(/.*)?$"
				}
			} else if strings.HasSuffix(raw, "/") {
				// 处理以 / 结尾的路径
				base := strings.TrimSuffix(raw, "/")
				converted := wildcardToRegex(base)
				if strings.HasPrefix(base, "/") {
					pattern = "^" + converted + "(/.*)?$"
				} else {
					pattern = "^/?" + converted + "(/.*)?$"
				}
			} else {
				converted := wildcardToRegex(raw)
				if strings.HasPrefix(raw, "^") {
					pattern = converted
				} else if strings.HasPrefix(raw, "/") {
					pattern = "^" + converted
				} else {
					pattern = "^/?" + converted
				}
			}

			t.Logf("Config path: %q", tc.configPath)
			t.Logf("Generated pattern: %s", pattern)

			reg, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatalf("Failed to compile pattern: %v", err)
			}

			for _, testPath := range tc.testPaths {
				matched := reg.MatchString(testPath)
				t.Logf("  Test path %q: matched=%v (expected=%v)", testPath, matched, tc.shouldMatch)
				if matched != tc.shouldMatch {
					t.Errorf("Path %q: expected match=%v, got %v", testPath, tc.shouldMatch, matched)
				}
			}
		})
	}
}

// TestActualPathConfig 测试用户实际的配置
func TestActualPathConfig(t *testing.T) {
	// 用户在 alist-encrypt 中配置的路径（逗号分隔）
	configPaths := []string{
		"/local_stroge/",
		"移动云盘156/encrypt/",  // 没有前导 /
		"/移动云盘192/encrypt/",
		"/156天翼云盘/天翼云盘/encrypt/",
		"/156联通云盘/encrypt/",
		"/豆包云/encrypt/",
		"/谷歌云盘1992/",
		"/谷歌云盘1991/",
	}

	// 模拟的文件路径
	testFiles := map[string]string{
		"/移动云盘156/encrypt/87kdQg0Y5VOWIUjeU~Xtcg435V+YO0--y.mp4": "移动云盘156/encrypt/",
		"/156联通云盘/encrypt/test.mp4":                              "/156联通云盘/encrypt/",
		"/谷歌云盘1992/test.mp4":                                     "/谷歌云盘1992/",
	}

	wildcardToRegex := func(raw string) string {
		a := "__AST__"
		q := "__QST__"
		tmp := strings.ReplaceAll(raw, "*", a)
		tmp = strings.ReplaceAll(tmp, "?", q)
		tmp = regexp.QuoteMeta(tmp)
		tmp = strings.ReplaceAll(tmp, a, ".*")
		tmp = strings.ReplaceAll(tmp, q, ".")
		return tmp
	}

	// 编译所有配置路径的正则
	type regexPath struct {
		path  string
		regex *regexp.Regexp
	}
	var regexPaths []regexPath

	for _, raw := range configPaths {
		var pattern string

		if strings.HasSuffix(raw, "/*") {
			base := strings.TrimSuffix(raw, "/*")
			converted := wildcardToRegex(base)
			if strings.HasPrefix(base, "/") {
				pattern = "^" + converted + "(/.*)?$"
			} else {
				pattern = "^/?" + converted + "(/.*)?$"
			}
		} else if strings.HasSuffix(raw, "/") {
			base := strings.TrimSuffix(raw, "/")
			converted := wildcardToRegex(base)
			if strings.HasPrefix(base, "/") {
				pattern = "^" + converted + "(/.*)?$"
			} else {
				pattern = "^/?" + converted + "(/.*)?$"
			}
		} else {
			converted := wildcardToRegex(raw)
			if strings.HasPrefix(raw, "^") {
				pattern = converted
			} else if strings.HasPrefix(raw, "/") {
				pattern = "^" + converted + "(/.*)?$"
			} else {
				pattern = "^/?" + converted + "(/.*)?$"
			}
		}

		t.Logf("Config: %q -> Pattern: %s", raw, pattern)

		reg, err := regexp.Compile(pattern)
		if err != nil {
			t.Fatalf("Failed to compile pattern for %q: %v", raw, err)
		}
		regexPaths = append(regexPaths, regexPath{path: raw, regex: reg})
	}

	// 测试匹配
	for testPath, expectedConfig := range testFiles {
		t.Run(testPath, func(t *testing.T) {
			var matched *regexPath
			for i := range regexPaths {
				if regexPaths[i].regex.MatchString(testPath) {
					matched = &regexPaths[i]
					break
				}
			}

			if matched == nil {
				t.Errorf("No match found for %q (expected %q)", testPath, expectedConfig)
			} else if matched.path != expectedConfig {
				t.Errorf("Wrong match for %q: got %q, expected %q", testPath, matched.path, expectedConfig)
			} else {
				t.Logf("Correctly matched %q -> %q", testPath, matched.path)
			}
		})
	}
}
