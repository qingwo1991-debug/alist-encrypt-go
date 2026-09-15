package handler

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// nextEpisodeSiblingDisplayPath derives the display path of the numerically
// next episode sibling for a given display path, following common episode
// naming conventions. It returns "" when the filename does not carry an
// unambiguous, incrementable episode number — callers must then do nothing.
//
// Design note: it only REARRANGES the existing name (increments the episode
// number) and never invents a directory or extension. The caller is required
// to verify the returned sibling exists in the local fileDAO cache (populated
// only by real upstream listings) before enqueuing anything: a wrong guess
// can never fabricate an upstream metadata call.
func nextEpisodeSiblingDisplayPath(displayPath string) string {
	base := strings.TrimSpace(path.Base(displayPath))
	if base == "" || strings.HasPrefix(base, ".") {
		return ""
	}
	dir := path.Dir(displayPath)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if stem == "" {
		return ""
	}
	nextStem, ok := incrementEpisodeSuffix(stem)
	if !ok || nextStem == stem {
		return ""
	}
	return path.Join(dir, nextStem+ext)
}

var digitRe = regexp.MustCompile(`[0-9]+`)

// cjkEpisodeUnits are the CJK chars that directly follow an episode number.
const cjkEpisodeUnits = "集话話卷章回期"

// episodeMarkerRe matches a Latin episode marker immediately preceding the
// final digit run: "Episode 12", "EP 12", "E12", "S01E05", "Part 8", "PT8".
// Group 1 = marker text, Group 2 = the digits.
var episodeMarkerRe = regexp.MustCompile(`(?i)^(.*?)(?:episode|ep|e|part|pt)\s*[.\-_ ]?([0-9]+)$`)

// bareEpisodeRe matches a bare trailing episode number separated by a
// separator: "Show Name 12", "Show.12", "Show - 12", "Show_12".
// Group 1 = prefix, Group 2 = digits.
var bareEpisodeRe = regexp.MustCompile(`^(.+[a-zA-Z0-9])[\s._-]+([0-9]+)$`)

// incrementEpisodeSuffix returns the stem (no extension) with its episode
// number incremented, ok=false when the stem has no safe, incrementable
// episode number.
//
// Supported layouts, in priority order:
//  1. CJK ordinal:  第12集 / 12话 / 第08卷（digits followed by a CJK unit）
//  2. Latin marker: Episode 12 / EP 12 / E12 / S01E05 / Part 8 / Pt 8
//  3. Bare trailing: "Show Name 12" —— only with a lettered prefix, so a bare
//     "12" or "1999" is never fabric-contented as an episode.
func incrementEpisodeSuffix(stem string) (string, bool) {
	stem = strings.TrimSpace(stem)
	if stem == "" {
		return "", false
	}

	// 1. CJK ordinal. Only treat it as the episode counter when the unit is the
	//   end of the stem: "第12集上/下" split-parts must not chain to "第13集".
	for _, r := range digitRe.FindAllStringIndex(stem, -1) {
		if r[1] >= len(stem) {
			continue
		}
		nxt, size := utf8.DecodeRuneInString(stem[r[1]:])
		if !strings.ContainsRune(cjkEpisodeUnits, nxt) {
			continue
		}
		// unit must be the stem tail (only trailing whitespace tolerated)
		if strings.TrimSpace(stem[r[1]+size:]) == "" {
			out, ok := bumpRun(stem, r[0], r[1])
			return out, ok
		}
	}

	// 2. Latin marker.
	if m := episodeMarkerRe.FindStringSubmatch(stem); len(m) == 3 {
		out, ok := bumpRunSuffix(stem, len(m[2]))
		if ok {
			return out, true
		}
	}

	// 3. Bare trailing number.
	if b := bareEpisodeRe.FindStringSubmatch(stem); len(b) == 3 && hasLetter(b[1]) {
		sepStart := len(b[1])
		sepEnd := len(stem) - len(b[2])
		if n, err := strconv.Atoi(b[2]); err == nil && n > 0 {
			return b[1] + stem[sepStart:sepEnd] + padNum(b[2], n+1), true
		}
	}

	return "", false
}

// bumpRun replaces the digits stem[start:end] with the incremented value.
func bumpRun(stem string, start, end int) (string, bool) {
	if end <= start {
		return "", false
	}
	n, err := strconv.Atoi(stem[start:end])
	if err != nil || n <= 0 {
		return "", false
	}
	return stem[:start] + padNum(stem[start:end], n+1) + stem[end:], true
}

// bumpSuffixSuffix replaces the LAST len(suffix) digits at the end of stem.
func bumpRunSuffix(stem string, digitLen int) (string, bool) {
	if digitLen <= 0 || digitLen > len(stem) {
		return "", false
	}
	start := len(stem) - digitLen
	return bumpRun(stem, start, len(stem))
}

func padNum(orig string, next int) string {
	if next <= 0 {
		return orig
	}
	if strings.HasPrefix(orig, "0") && len(orig) > 1 {
		return fmt.Sprintf("%0*d", len(orig), next)
	}
	return strconv.Itoa(next)
}

func hasLetter(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}
