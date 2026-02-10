package mysqlstore

import "testing"

func TestTableNamePrefix(t *testing.T) {
	name := TableName("strategy")
	if name != "alist_encrypt_strategy" {
		t.Fatalf("expected table name with prefix, got %s", name)
	}
	meta := TableName("file_meta")
	if meta != "alist_encrypt_file_meta" {
		t.Fatalf("expected file meta table name with prefix, got %s", meta)
	}
}
