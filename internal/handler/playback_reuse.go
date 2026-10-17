package handler

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "fmt"
 "net/http"
 "time"

 "github.com/alist-encrypt-go/internal/config"
 "github.com/alist-encrypt-go/internal/dao"
 "github.com/alist-encrypt-go/internal/ports"
 encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

type playbackCacheRepository interface {
 PlaybackEpoch(string) uint64
 GetConfirmedPlayback(string)(*dao.FileInfo,bool)
 PublishConfirmedPlayback(*dao.FileInfo,uint64) bool
 PublishPlaybackInfo(*dao.FileInfo,uint64) bool
 DoPlaybackLoad(context.Context,string,func(context.Context)(interface{},error))(interface{},error)
}
func playbackScope(cfg *config.Config,headers http.Header) string {
 if cfg!=nil && cfg.AlistServerSnapshot().PlaybackProfile==config.PlaybackProfileTrustedLocal{return "trusted_local"}
 return rawURLAuthScope(headers)
}
func playbackIdentity(cfg *config.Config,origin,raw string,passwd *config.PasswdInfo,headers http.Header) string {
 rule:="";if passwd!=nil{rule=filenameRuleScope(passwd)}
 profile:="standard";if cfg!=nil{profile=cfg.AlistServerSnapshot().PlaybackProfile}
 sum:=sha256.Sum256([]byte(origin+"\x00"+raw+"\x00"+rule+"\x00"+profile+"\x00"+playbackScope(cfg,headers)))
 return hex.EncodeToString(sum[:])
}
func confirmedPlaybackMeta(req decryptPlaybackRequest,headers http.Header,fallback int64)(encryption.ContentMeta,bool){
 repo,ok:=req.FileDAO.(playbackCacheRepository)
 if !ok || req.Config==nil || req.Request==nil || req.FileItem.DisplayPath=="" || req.FileItem.EncryptedPath=="" {return inspectPlaybackContentMeta(req,headers,fallback)}
 origin,revision:=req.Config.GetAlistURL(),req.Config.RuntimeRevision()
 identity:=playbackIdentity(req.Config,origin,req.FileItem.EncryptedPath,req.PasswdInfo,headers)
 epoch:=repo.PlaybackEpoch(req.FileItem.DisplayPath)
 if info,hit:=repo.GetConfirmedPlayback(identity);hit {if meta,complete:=cachedPlaybackMeta(info,req.PasswdInfo.EncType);complete{return meta,true}}
 key:=fmt.Sprintf("geometry:%s:%d:%d",identity,epoch,revision)
 value,err:=repo.DoPlaybackLoad(req.Request.Context(),key,func(ctx context.Context)(interface{},error){
  if info,hit:=repo.GetConfirmedPlayback(identity);hit {if meta,complete:=cachedPlaybackMeta(info,req.PasswdInfo.EncType);complete{return meta,nil}}
  owned:=req;owned.Request=req.Request.Clone(ctx)
  meta,confirmed:=inspectPlaybackContentMeta(owned,headers,fallback)
  if !confirmed{return nil,fmt.Errorf("content inspection unconfirmed")}
  if ctx.Err()!=nil || req.Config.RuntimeRevision()!=revision || req.Config.GetAlistURL()!=origin || repo.PlaybackEpoch(req.FileItem.DisplayPath)!=epoch{return nil,fmt.Errorf("content inspection invalidated")}
  info:=playbackMetaInfo(req,meta)
  info.GeometryIdentity,info.GeometryConfirmedAt=identity,time.Now()
  if _,complete:=cachedPlaybackMeta(info,req.PasswdInfo.EncType);!complete{return nil,fmt.Errorf("content inspection incomplete")}
  if !repo.PublishConfirmedPlayback(info,epoch){return nil,fmt.Errorf("content publication invalidated")}
  return meta,nil
 })
 if err!=nil || value==nil{return encryption.ContentMeta{},false}
 if req.Config.RuntimeRevision()!=revision || repo.PlaybackEpoch(req.FileItem.DisplayPath)!=epoch{return encryption.ContentMeta{},false}
 meta,ok:=value.(encryption.ContentMeta);return meta,ok
}
func playbackMetaInfo(req decryptPlaybackRequest,meta encryption.ContentMeta)*dao.FileInfo{
 return &dao.FileInfo{Path:req.FileItem.DisplayPath,EncryptedPath:req.FileItem.EncryptedPath,Name:req.FileItem.FileName,Size:meta.PlainSize,CiphertextSize:meta.TotalCiphertextSize(),ContentVersion:meta.Version,HeaderLen:meta.HeaderLen,NonceField:append([]byte(nil),meta.NonceField...),ChunkSize:meta.ChunkSize,KDFIterations:meta.KDFIterations}
}

// No raw URL response size may overwrite confirmed plaintext/container geometry.
func publishPlaybackTransport(files ports.FileRepository,info *dao.FileInfo,epoch uint64)bool{
 if repo,ok:=files.(playbackCacheRepository);ok{return repo.PublishPlaybackInfo(info,epoch)}
 return files.Set(info)==nil
}
