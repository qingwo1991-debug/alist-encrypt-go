package handler

import "testing"

func TestSnapshotPayloadRootPoisonedPositive(t *testing.T) {
	h := &AlistHandler{}
	h.rememberRootMounts([]byte(`{"code":0,"data":{"content":[
		{"name":"156天翼云盘","size":0,"is_dir":true},
		{"name":"移动云盘156","size":0,"is_dir":true},
		{"name":"omv","size":0,"is_dir":true},
		{"name":"老婆的","size":0,"is_dir":true},
		{"name":"谷歌云盘1991","size":0,"is_dir":true},
		{"name":"豆包云","size":0,"is_dir":true}
	]}}`))

	// A drive-root masquerade: the large majority of entries are known top-level
	// drive mounts, zero files. Must be flagged even though a few names in the
	// attacker's snapshot are config-uncovered drives listed in the payload.
	payload := []byte(`{"code":200,"data":{"content":[
		{"name":"156天翼云盘","size":0,"is_dir":true},
		{"name":"156天翼云盘个人","size":0,"is_dir":true},
		{"name":"156联通云盘","size":0,"is_dir":true},
		{"name":"omv","size":0,"is_dir":true},
		{"name":"移动云盘156","size":0,"is_dir":true},
		{"name":"老婆的","size":0,"is_dir":true},
		{"name":"谷歌云盘1991","size":0,"is_dir":true},
		{"name":"谷歌云盘1992","size":0,"is_dir":true},
		{"name":"豆包云","size":0,"is_dir":true},
		{"name":"移动云盘192","size":0,"is_dir":true}
	]}}`)
	if !h.snapshotPayloadRootPoisoned("/156联通云盘/encrypt", payload) {
		t.Fatal("root-listing masquerade was not flagged as poisoned")
	}
}

func TestSnapshotPayloadPoisonedNegativeGenuineAllDirs(t *testing.T) {
	h := &AlistHandler{}

	// A real directory that legitimately contains only subdirectories whose
	// names are content names (a cover-index dir / VIDEO_TS tree). Must NOT
	// be flagged — this is exactly the misclassification the previous guard
	// made on /156天翼云盘/.../avv/avv/avv and /...babytong/Cshot.
	cases := []struct{ name string }{
		{"VIDEO_TS"},
		{"[bbs.yzkof.com]花と蛇[约战竞技场]"},
		{"梅脱因.三部曲"},
		{"Art & Design"},
	}
	for _, path := range []string{
		"/156天翼云盘/天翼云盘/encrypt/avv/avv/avv",
		"/156天翼云盘/天翼云盘/encrypt/avv/avv/女系家族III",
		"/移动云盘192/babytong/Pindd",
		"/移动云盘192/babytong/Cshot",
	} {
		payload := `{"code":0,"data":{"content":[`
		for i, c := range cases {
			if i > 0 {
				payload += ","
			}
			payload += `{"name":"` + c.name + `","size":0,"is_dir":true}`
		}
		payload += `]}}`
		if h.snapshotPayloadRootPoisoned(path, []byte(payload)) {
			t.Fatalf("genuine all-directory dir %s was misclassified as poisoned", path)
		}
	}
}

func TestSnapshotPayloadRootPoisonedWithFilesIsNeverPoisoned(t *testing.T) {
	h := &AlistHandler{}
	payload := []byte(`{"code":0,"data":{"content":[
		{"name":"156天翼云盘","size":0,"is_dir":true},
		{"name":"bbs.yzkof.com-18.mp4","size":123,"is_dir":false}
	]}}`)
	if h.snapshotPayloadRootPoisoned("/whatever/encrypt", payload) {
		t.Fatal("payload containing a file must never be treated as a root listing")
	}
}

func TestSnapshotPayloadRootPoisonedRootPathNever(t *testing.T) {
	h := &AlistHandler{}
	rootname := []byte(`{"code":0,"data":{"content":[
		{"name":"移动云盘156","size":0,"is_dir":true}
	]}}`)
	if h.snapshotPayloadRootPoisoned("/", rootname) {
		t.Fatal("root path itself should never be treated as poisoned")
	}
}
