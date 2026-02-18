package config

import "testing"

func TestNormalizeUserEncPaths(t *testing.T) {
	input := []string{
		",/personal_cloud/encrypt/*",
		" /personal_cloud/encrypt/* ",
		"/d/personal_cloud/encrypt/*",
		"/p/personal_cloud/encrypt/*",
		"/dav/personal_cloud/encrypt/*",
		"/d/d/personal_cloud/encrypt/*",
		"/duser_storage/encrypt/*",
		"",
	}

	got := NormalizeUserEncPaths(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 normalized paths, got %d: %#v", len(got), got)
	}
	if got[0] != "/personal_cloud/encrypt/*" {
		t.Fatalf("unexpected first path: %q", got[0])
	}
	if got[1] != "/user_storage/encrypt/*" {
		t.Fatalf("unexpected second path: %q", got[1])
	}
}

func TestNormalizeUserEncPathsKeepRegularEnglishPrefix(t *testing.T) {
	input := []string{
		"/data/encrypt/*",
		"/private/encrypt/*",
		"/davinci/encrypt/*",
	}

	got := NormalizeUserEncPaths(input)
	if len(got) != 3 {
		t.Fatalf("expected 3 paths, got %d: %#v", len(got), got)
	}
	if got[0] != "/data/encrypt/*" || got[1] != "/private/encrypt/*" || got[2] != "/davinci/encrypt/*" {
		t.Fatalf("unexpected normalized paths: %#v", got)
	}
}

func TestNormalizePasswdListEncPathsChanged(t *testing.T) {
	passwds := []PasswdInfo{
		{
			EncPath: []string{
				"/encrypt/*",
				"/d/encrypt/*",
				"/p/encrypt/*",
				"/dav/encrypt/*",
			},
		},
	}

	changed := normalizePasswdListEncPaths(passwds)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if len(passwds[0].EncPath) != 1 || passwds[0].EncPath[0] != "/encrypt/*" {
		t.Fatalf("unexpected normalized passwd paths: %#v", passwds[0].EncPath)
	}
}
