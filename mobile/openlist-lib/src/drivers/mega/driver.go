package mega

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/pquerna/otp/totp"
	"github.com/rclone/rclone/lib/readers"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	opnet "github.com/OpenListTeam/OpenList/v4/internal/net"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	log "github.com/sirupsen/logrus"
	"github.com/t3rm1n4l/go-mega"
)

type Mega struct {
	model.Storage
	Addition
	c             *mega.Mega
	clientRelease func()
	dropOnce      sync.Once
	sessionStop   func() bool
}

func (d *Mega) Config() driver.Config {
	return config
}

func (d *Mega) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *Mega) Init(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var twoFACode = d.TwoFACode
	if d.TwoFASecret != "" {
		code, err := totp.GenerateCode(d.TwoFASecret, time.Now())
		if err != nil {
			return fmt.Errorf("generate totp code failed: %w", err)
		}
		twoFACode = code
	}
	client := mega.New()
	identity, ok := opnet.DriverRouteIdentityFromContext(ctx)
	if !ok {
		identity = opnet.DriverRouteIdentity{Driver: d.Config().Name, Storage: fmt.Sprint(d.ID)}
	}
	httpClient, release := opnet.NewDriverHTTPClient(identity, 0)
	client.SetClient(httpClient)
	err := client.MultiFactorLoginContext(ctx, d.Email, d.Password, twoFACode)
	if err != nil {
		_ = client.Close()
		release()
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = client.Close()
		release()
		return ctxErr
	}
	// Generation cancellation cancels SDK lifetime without blocking AfterFunc
	// on a join; explicit Drop below performs the actual join before release.
	d.sessionStop = context.AfterFunc(opnet.StorageSessionContext(ctx), client.CancelSession)
	d.c = client
	d.clientRelease = release
	d.dropOnce = sync.Once{}
	return nil
}

func (d *Mega) Drop(ctx context.Context) error {
	var err error
	d.dropOnce.Do(func() {
		if d.sessionStop != nil {
			d.sessionStop()
		}
		if d.c != nil {
			err = d.c.Close()
		}
		if d.clientRelease != nil {
			d.clientRelease()
		}
	})
	return err
}

func (d *Mega) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if node, ok := dir.(*MegaNode); ok {
		nodes, err := d.c.FS.GetChildren(node.n)
		if err != nil {
			return nil, err
		}
		fn := make(map[string]model.Obj)
		for i := range nodes {
			n := nodes[i]
			if n.GetType() != mega.FILE && n.GetType() != mega.FOLDER {
				continue
			}
			if _, ok := fn[n.GetName()]; !ok {
				fn[n.GetName()] = &MegaNode{n}
			} else if sameNameObj := fn[n.GetName()]; (&MegaNode{n}).ModTime().After(sameNameObj.ModTime()) {
				fn[n.GetName()] = &MegaNode{n}
			}
		}
		res := make([]model.Obj, 0)
		for _, v := range fn {
			res = append(res, v)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return res, nil
	}
	log.Errorf("can't convert: %+v", dir)
	return nil, fmt.Errorf("unable to convert dir to mega n")
}

func (d *Mega) GetRoot(ctx context.Context) (model.Obj, error) {
	n := d.c.FS.GetRoot()
	log.Debugf("mega root: %+v", *n)
	return &MegaNode{n}, nil
}

func (d *Mega) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	if node, ok := file.(*MegaNode); ok {

		//down, err := d.c.NewDownload(n.Node)
		//if err != nil {
		//	return nil, fmt.Errorf("open download file failed: %w", err)
		//}

		size := file.GetSize()
		resultRangeReader := func(ctx context.Context, httpRange http_range.Range) (io.ReadCloser, error) {
			length := httpRange.Length
			if httpRange.Length < 0 || httpRange.Start+httpRange.Length >= size {
				length = size - httpRange.Start
			}
			var down *mega.Download
			err := utils.RetryContext(ctx, 3, time.Second, func() (err error) {
				down, err = d.c.NewDownloadContext(ctx, node.n)
				return err
			})
			if err != nil {
				return nil, fmt.Errorf("open download file failed: %w", err)
			}
			readerCtx, cancel := context.WithCancel(ctx)
			oo := &openObject{
				ctx:    readerCtx,
				cancel: cancel,
				d:      down,
				skip:   httpRange.Start,
			}

			return readers.NewLimitedReadCloser(oo, length), nil
		}
		return &model.Link{
			RangeReader: stream.RateLimitRangeReaderFunc(resultRangeReader),
		}, nil
	}
	return nil, fmt.Errorf("unable to convert dir to mega n")
}

func (d *Mega) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	if parentNode, ok := parentDir.(*MegaNode); ok {
		_, err := d.c.CreateDirContext(ctx, dirName, parentNode.n)
		return err
	}
	return fmt.Errorf("unable to convert dir to mega n")
}

func (d *Mega) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	if srcNode, ok := srcObj.(*MegaNode); ok {
		if dstNode, ok := dstDir.(*MegaNode); ok {
			return d.c.MoveContext(ctx, srcNode.n, dstNode.n)
		}
	}
	return fmt.Errorf("unable to convert dir to mega n")
}

func (d *Mega) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	if srcNode, ok := srcObj.(*MegaNode); ok {
		return d.c.RenameContext(ctx, srcNode.n, newName)
	}
	return fmt.Errorf("unable to convert dir to mega n")
}

func (d *Mega) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	return errs.NotImplement
}

func (d *Mega) Remove(ctx context.Context, obj model.Obj) error {
	if node, ok := obj.(*MegaNode); ok {
		return d.c.DeleteContext(ctx, node.n, !d.MoveToTrash)
	}
	return fmt.Errorf("unable to convert dir to mega n")
}

func (d *Mega) Put(ctx context.Context, dstDir model.Obj, stream model.FileStreamer, up driver.UpdateProgress) error {
	if dstNode, ok := dstDir.(*MegaNode); ok {
		u, err := d.c.NewUploadContext(ctx, dstNode.n, stream.GetName(), stream.GetSize())
		if err != nil {
			return err
		}

		reader := driver.NewLimitedUploadStream(ctx, stream)
		for id := 0; id < u.Chunks(); id++ {
			if utils.IsCanceled(ctx) {
				return ctx.Err()
			}
			_, chkSize, err := u.ChunkLocation(id)
			if err != nil {
				return err
			}
			chunk := make([]byte, chkSize)
			n, err := io.ReadFull(reader, chunk)
			if err != nil && err != io.EOF {
				return err
			}
			if n != len(chunk) {
				return errors.New("chunk too short")
			}

			err = u.UploadChunkContext(ctx, id, chunk)
			if err != nil {
				return err
			}
			up(float64(id) * 100 / float64(u.Chunks()))
		}

		_, err = u.FinishContext(ctx)
		return err
	}
	return fmt.Errorf("unable to convert dir to mega n")
}

func (d *Mega) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	quota, err := d.c.GetQuotaContext(ctx)
	if err != nil {
		return nil, err
	}
	return &model.StorageDetails{
		DiskUsage: model.DiskUsage{
			TotalSpace: int64(quota.Mstrg),
			UsedSpace:  int64(quota.Cstrg),
		},
	}, nil
}

//func (d *Mega) Other(ctx context.Context, args model.OtherArgs) (interface{}, error) {
//	return nil, errs.NotSupport
//}

var _ driver.Driver = (*Mega)(nil)
