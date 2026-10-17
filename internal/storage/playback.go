package storage

import (
 "encoding/json"
 bolt "go.etcd.io/bbolt"
)

// Playback cache is rebuildable and deliberately separate from filename audit.
var playbackBucket = []byte("playback_confirmed_v1")
func (s *Store) GetPlayback(key string, value interface{}) error {
 return s.db.View(func(tx *bolt.Tx) error {
  b:=tx.Bucket(playbackBucket); if b==nil { return nil }; v:=b.Get([]byte(key)); if v==nil { return nil }; return json.Unmarshal(v,value)
 })
}
func (s *Store) SetPlayback(key string,value interface{}) error {
 data,err:=json.Marshal(value); if err!=nil{return err}
 return s.update(func(tx *bolt.Tx) error { b,e:=tx.CreateBucketIfNotExists(playbackBucket);if e!=nil{return e};return b.Put([]byte(key),data) })
}
func (s *Store) ClearPlayback() error {
 return s.update(func(tx *bolt.Tx) error {if tx.Bucket(playbackBucket)==nil{return nil};return tx.DeleteBucket(playbackBucket)})
}
