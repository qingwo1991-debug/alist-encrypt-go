package dao

import (
 "context"
 "errors"
 "sync"
 "time"
)

// playbackState belongs to FileDAO. Invalidation fences durable publication;
// canceled loads retain admission until the actual worker exits. Stop joins IO.
type playbackState struct {
 mu sync.Mutex
 epoch uint64
 flights map[string]*playbackFlight
 confirmed map[string]FileInfo
 stopped bool
 wg sync.WaitGroup
}
type playbackFlight struct {
 done chan struct{}
 cancel context.CancelFunc
 waiters int
 value interface{}
 err error
}
func (d *FileDAO) PlaybackEpoch(_ string) uint64 {
 d.playback.mu.Lock(); defer d.playback.mu.Unlock(); return d.playback.epoch
}
func (d *FileDAO) GetConfirmedPlayback(identity string) (*FileInfo,bool) {
 s:=&d.playback; s.mu.Lock(); defer s.mu.Unlock()
 if s.stopped{return nil,false}
 info,ok:=s.confirmed[identity]
 if !ok && d.store!=nil { if d.store.GetPlayback(identity,&info)==nil {ok=info.GeometryIdentity==identity} }
 age:=time.Since(info.GeometryConfirmedAt)
 if !ok || info.GeometryIdentity!=identity || info.GeometryConfirmedAt.IsZero() || age<0 || age>=24*time.Hour{return nil,false}
 info.NonceField=append([]byte(nil),info.NonceField...)
 return &info,true
}
func (d *FileDAO) PublishConfirmedPlayback(info *FileInfo,epoch uint64) bool {
 s:=&d.playback;s.mu.Lock();defer s.mu.Unlock()
 if info==nil || info.GeometryIdentity=="" || s.stopped || s.epoch!=epoch{return false}
 copy:=*info;copy.NonceField=append([]byte(nil),info.NonceField...)
 if d.store!=nil {if err:=d.store.SetPlayback(copy.GeometryIdentity,&copy);err!=nil{return false}}
 if s.confirmed==nil{s.confirmed=make(map[string]FileInfo)}
 if len(s.confirmed)>=2048 {for k:=range s.confirmed {delete(s.confirmed,k);break}}
 s.confirmed[copy.GeometryIdentity]=copy
 // Legacy consumers still see the same complete geometry. Dedicated Bolt
 // confirmation above, rather than optional MySQL write-behind, owns restart.
 _=d.Set(&copy)
 return true
}
func (d *FileDAO) PublishPlaybackInfo(info *FileInfo,epoch uint64) bool {
 s:=&d.playback;s.mu.Lock();defer s.mu.Unlock()
 if info==nil||s.stopped||s.epoch!=epoch{return false};return d.Set(info)==nil
}
func (d *FileDAO) DoPlaybackLoad(ctx context.Context,key string,load func(context.Context)(interface{},error))(interface{},error){
 if err:=ctx.Err();err!=nil{return nil,err}
 s:=&d.playback;s.mu.Lock()
 if s.stopped{s.mu.Unlock();return nil,errors.New("playback cache stopped")}
 if s.flights==nil{s.flights=make(map[string]*playbackFlight)}
 f:=s.flights[key]
 if f==nil {
  if len(s.flights)>=128{s.mu.Unlock();return nil,errors.New("playback cache admission busy")}
  work,cancel:=context.WithTimeout(context.WithoutCancel(ctx),15*time.Second)
  f=&playbackFlight{done:make(chan struct{}),cancel:cancel};s.flights[key]=f;s.wg.Add(1)
  go func(){
   defer s.wg.Done();defer cancel();value,err:=load(work)
   s.mu.Lock();f.value,f.err=value,err;delete(s.flights,key);close(f.done);s.mu.Unlock()
  }()
 }
 f.waiters++;s.mu.Unlock()
 defer func(){s.mu.Lock();f.waiters--;if f.waiters==0{f.cancel()};s.mu.Unlock()}()
 select {case <-ctx.Done():return nil,ctx.Err();case <-f.done:if err:=ctx.Err();err!=nil{return nil,err};return f.value,f.err}
}
func (d *FileDAO) invalidatePlaybackLocked(){
 d.playback.epoch++
 d.playback.confirmed=nil
 if d.store!=nil{_ = d.store.ClearPlayback()}
 for _,f:=range d.playback.flights{f.cancel()}
}
func (d *FileDAO) stopPlayback(){
 s:=&d.playback;s.mu.Lock();s.stopped=true;for _,f:=range s.flights{f.cancel()};s.mu.Unlock();s.wg.Wait()
}
