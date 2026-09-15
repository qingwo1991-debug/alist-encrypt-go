package handler

import "testing"

func TestNextEpisodeSiblingDisplayPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// CJK ordinal
		{"/drama/第01集.mp4", "/drama/第02集.mp4"},
		{"/drama/第12集.mp4", "/drama/第13集.mp4"},
		{"/drama/第8话.mkv", "/drama/第9话.mkv"},
		{"/drama/第08卷.mkv", "/drama/第09卷.mkv"},
		// Latin markers
		{"/d/EP01.mp4", "/d/EP02.mp4"},
		{"/d/episode 12.mkv", "/d/episode 13.mkv"},
		{"/d/Episode.12.mkv", "/d/Episode.13.mkv"},
		{"/d/E3.mp4", "/d/E4.mp4"},
		{"/d/S01E05.mp4", "/d/S01E06.mp4"},
		{"/d/Part 8.mp4", "/d/Part 9.mp4"},
		{"/d/Pt8.mp4", "/d/Pt9.mp4"},
		// Bare trailing number (lettered prefix only)
		{"/d/Show Name 12.mp4", "/d/Show Name 13.mp4"},
		{"/d/show.12.mkv", "/d/show.13.mkv"},
		{"/d/show - 08.mp4", "/d/show - 09.mp4"},
		{"/d/show_23.mp4", "/d/show_24.mp4"},
	}
	for _, c := range cases {
		if got := nextEpisodeSiblingDisplayPath(c.in); got != c.want {
			t.Errorf("nextEpisodeSiblingDisplayPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNextEpisodeSiblingDisplayPathSkipsAmbiguous(t *testing.T) {
	skips := []string{
		"/d/12.mp4",     // pure numeric basename — too ambiguous
		"/d/1999.mkv",   // looks like a year
		"/d/plain.mp4",  // no digits
		"/d/.hidden",    // dotfile
		"/d/name.mp4",   // no episode marker (name not an episode pattern)
		"/d/第12集 上.mp4", // CJK unit followed by more text — not a plain counter
	}
	for _, in := range skips {
		if got := nextEpisodeSiblingDisplayPath(in); got != "" {
			t.Errorf("nextEpisodeSiblingDisplayPath(%q) = %q, want \"\" (ambiguous)", in, got)
		}
	}
}

func TestIncrementEpisodeSuffixPadding(t *testing.T) {
	cases := []struct{ in, want string }{
		{"EP09", "EP10"},  // leading-zero width preserved
		{"EP99", "EP100"}, // width grows past 2 digits
		{"E09", "E10"},
		{"/", "/"}, // no-op safe
	}
	for _, c := range cases {
		if c.in == "/" {
			continue
		}
		if got, ok := incrementEpisodeSuffix(c.in); !ok || got != c.want {
			t.Errorf("incrementEpisodeSuffix(%q) = %q,%v want %q,true", c.in, got, ok, c.want)
		}
	}
}
