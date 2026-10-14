package mysqlstore

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These assertions execute the actual predicates on MySQL, not a SQL mock.
// MYSQL_TEST_DSN opts in using the same isolated-database fixture as V3 tests.
func TestMySQLListFileMetaIntegration(t *testing.T) {
	ctx, s, _ := newMySQLIntegrationStore(t)
	// Exercise upgraded installations with fractional DATETIME columns as well
	// as legacy seconds; casting to DATETIME(0) would round some of these rows.
	if _, err := s.db.ExecContext(ctx, "ALTER TABLE "+TableName("file_meta")+" MODIFY updated_at DATETIME(6) NOT NULL"); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	insert := func(key, provider, path string, updated time.Time, active bool) {
		t.Helper()
		if err := s.upsertFileMeta(ctx, []FileMetaRecord{{KeyHash: key, ProviderHost: provider, OriginalPath: path, UpdatedAt: updated, Active: active}}); err != nil {
			t.Fatal(err)
		}
	}
	list := func(filter FileMetaFilter) []FileMetaRecord {
		t.Helper()
		got, err := s.ListFileMeta(ctx, filter)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	keys := func(records []FileMetaRecord) []string {
		out := make([]string, 0, len(records))
		for _, record := range records {
			out = append(out, record.KeyHash)
		}
		return out
	}
	hash := func(i int) string { return fmt.Sprintf("%032x", i) }

	t.Run("legacy_same_second_pages_lookahead_and_deleted_anchor", func(t *testing.T) {
		// Reverse fractional timestamp order deliberately: legacy ordering must
		// use key alone within a second, including >.5-second timestamps.
		for i := 1; i <= 7; i++ {
			insert(hash(i), "pages", fmt.Sprintf("/page/%d", i), base.Add(time.Duration(8-i)*100*time.Millisecond), true)
		}
		insert(hash(0), "pages", "/old", base.Add(-time.Second), true)
		insert(hash(8), "pages", "/next-second", base.Add(time.Second), true)
		insert(hash(9), "pages", "/inactive", base, false)
		filter := FileMetaFilter{ProviderHost: "pages", UpdatedAfter: base.Add(900 * time.Millisecond), LegacySeconds: true, Limit: 3}
		var seen []string
		pages := 0
		for {
			got := list(filter)
			if len(got) > 3 {
				t.Fatalf("explicit fetch count exceeded: %d", len(got))
			}
			pages++
			if pages > 10 {
				t.Fatal("pagination did not terminate")
			}
			hasMore := len(got) > 2
			visible := got
			if hasMore {
				visible = got[:2]
			}
			if len(visible) == 0 {
				t.Fatal("unexpected empty page")
			}
			seen = append(seen, keys(visible)...)
			if !hasMore {
				break
			}
			anchor := visible[len(visible)-1]
			if pages == 1 {
				if _, err := s.db.ExecContext(ctx, "DELETE FROM "+TableName("file_meta")+" WHERE key_hash=?", anchor.KeyHash); err != nil {
					t.Fatal(err)
				}
			}
			filter.CursorKey = anchor.KeyHash
			if pages == 1 {
				// Raw legacy hash uses since for its tuple timestamp.
				filter.CursorTime = time.Time{}
			} else {
				filter.CursorTime = anchor.UpdatedAt
			}
		}
		want := make([]string, 0, 8)
		for i := 1; i <= 8; i++ {
			want = append(want, hash(i))
		}
		if pages != 4 || !reflect.DeepEqual(seen, want) {
			t.Fatalf("pages=%d keys=%v want=%v", pages, seen, want)
		}
	})

	t.Run("precise_tuple_independent_of_inclusive_since", func(t *testing.T) {
		for i, nanos := range []time.Duration{100, 100, 200, 200, 300} {
			insert(hash(100+i), "precise", fmt.Sprintf("/precise/%d", i), base.Add(nanos*time.Millisecond), true)
		}
		got := list(FileMetaFilter{ProviderHost: "precise", UpdatedAfter: base.Add(100 * time.Millisecond), CursorTime: base.Add(200 * time.Millisecond), CursorKey: hash(102), Limit: 2})
		if !reflect.DeepEqual(keys(got), []string{hash(103), hash(104)}) {
			t.Fatalf("exclusive tuple not independent of since: %v", keys(got))
		}
		got = list(FileMetaFilter{ProviderHost: "precise", UpdatedAfter: base.Add(200 * time.Millisecond), Limit: 10})
		if !reflect.DeepEqual(keys(got), []string{hash(102), hash(103), hash(104)}) {
			t.Fatalf("since must be inclusive: %v", keys(got))
		}
		got = list(FileMetaFilter{ProviderHost: "precise", CursorTime: base.Add(200 * time.Millisecond), CursorKey: hash(102), Limit: 10})
		if !reflect.DeepEqual(keys(got), []string{hash(103), hash(104)}) {
			t.Fatalf("timestamped cursor requires no since: %v", keys(got))
		}
		got = list(FileMetaFilter{ProviderHost: "precise", UpdatedAfter: base.Add(300 * time.Millisecond), CursorTime: base.Add(100 * time.Millisecond), CursorKey: hash(100), Limit: 10})
		if !reflect.DeepEqual(keys(got), []string{hash(104)}) {
			t.Fatalf("cursor weakened since: %v", keys(got))
		}
	})

	t.Run("literal_case_sensitive_filters", func(t *testing.T) {
		prefix := "/Dir/=_%\\"
		paths := []string{prefix + "one", prefix + "two", "/dir/=_%\\one", "/Dir/=X%\\one", "/Dir/=_X\\one", "/Dir/X_%\\one"}
		for i, path := range paths {
			insert(hash(200+i), "Literal", path, base, true)
		}
		insert(hash(210), "literal", prefix+"three", base, true)
		got := list(FileMetaFilter{ProviderHost: "Literal", PathPrefix: prefix, Limit: 10})
		if !reflect.DeepEqual(keys(got), []string{hash(200), hash(201)}) {
			t.Fatalf("prefix interpreted wildcards, escape, or case: %v", keys(got))
		}
		got = list(FileMetaFilter{ProviderHost: "Literal", OriginalPath: paths[0], Limit: 10})
		if !reflect.DeepEqual(keys(got), []string{hash(200)}) {
			t.Fatalf("exact path/provider not literal: %v", keys(got))
		}
		got = list(FileMetaFilter{ProviderHost: "LITERAL", Limit: 10})
		if len(got) != 0 {
			t.Fatalf("provider case folded: %v", keys(got))
		}
	})

	t.Run("invalid_cursor_and_database_errors", func(t *testing.T) {
		for _, filter := range []FileMetaFilter{{CursorKey: hash(1)}, {CursorKey: hash(1), LegacySeconds: true}, {CursorKey: hash(1), UpdatedAfter: base}} {
			if _, err := s.ListFileMeta(ctx, filter); err == nil {
				t.Fatalf("accepted cursor without cursor time: %+v", filter)
			}
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := s.ListFileMeta(cancelled, FileMetaFilter{Limit: 1}); err == nil {
			t.Fatal("cancelled query error swallowed")
		}
		if _, err := s.db.ExecContext(ctx, "DROP TABLE "+TableName("file_meta")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ListFileMeta(ctx, FileMetaFilter{Limit: 1}); err == nil {
			t.Fatal("database query error swallowed")
		}
	})
}

func TestListFileMetaUnavailableStore(t *testing.T) {
	for _, s := range []*Store{nil, {}} {
		if _, err := s.ListFileMeta(context.Background(), FileMetaFilter{}); err == nil || !strings.Contains(err.Error(), "unavailable") {
			t.Fatalf("unavailable store: %v", err)
		}
	}
}
