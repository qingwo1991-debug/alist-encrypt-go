package _189

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
)

type Cloud189 struct {
	model.Storage
	Addition
	client     *resty.Client
	rsa        Rsa
	sessionKey string
}

func (d *Cloud189) Config() driver.Config {
	return config
}

func (d *Cloud189) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *Cloud189) Init(ctx context.Context) error {
	d.client = base.NewRestyClient().
		SetHeader("Referer", "https://cloud.189.cn/")
	return d.newLogin()
}

func (d *Cloud189) Drop(ctx context.Context) error {
	return nil
}

func (d *Cloud189) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	return d.getFiles(dir.GetID())
}

func (d *Cloud189) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	var resp DownResp
	u := "https://cloud.189.cn/api/portal/getFileInfo.action"
	_, err := d.request(u, http.MethodGet, func(req *resty.Request) {
		req.SetQueryParam("fileId", file.GetID())
	}, &resp)
	if err != nil {
		return nil, err
	}
	client := resty.NewWithClient(d.client.GetClient()).SetRedirectPolicy(
		resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}))
	currentURL := strings.TrimSpace(resp.FileDownloadUrl)
	if strings.HasPrefix(currentURL, "//") {
		currentURL = "https:" + currentURL
	} else if strings.HasPrefix(currentURL, "/") {
		currentURL = "https://cloud.189.cn" + currentURL
	}
	if parsed, parseErr := url.Parse(currentURL); parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("invalid download URL")
	}
	for hop := 0; hop < 3; hop++ {
		res, requestErr := client.R().SetHeader("User-Agent", base.UserAgent).Get(currentURL)
		if requestErr != nil {
			return nil, requestErr
		}
		log.Debugf("download redirect response hop=%d status=%d body_bytes=%d", hop, res.StatusCode(), len(res.Body()))
		if res.StatusCode() < http.StatusMultipleChoices || res.StatusCode() >= http.StatusBadRequest {
			if res.StatusCode() >= http.StatusBadRequest {
				return nil, fmt.Errorf("download URL request failed: status %d", res.StatusCode())
			}
			break
		}
		location := strings.TrimSpace(res.Header().Get("Location"))
		if location == "" {
			return nil, fmt.Errorf("download redirect missing Location")
		}
		baseURL, _ := url.Parse(currentURL)
		nextURL, resolveErr := url.Parse(location)
		if resolveErr != nil {
			return nil, fmt.Errorf("invalid download redirect")
		}
		nextURL = baseURL.ResolveReference(nextURL)
		if (nextURL.Scheme != "http" && nextURL.Scheme != "https") || nextURL.Host == "" {
			return nil, fmt.Errorf("unsafe download redirect scheme")
		}
		currentURL = nextURL.String()
	}
	currentURL = strings.Replace(currentURL, "http://", "https://", 1)
	return &model.Link{URL: currentURL}, nil
}

func (d *Cloud189) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	form := map[string]string{
		"parentFolderId": parentDir.GetID(),
		"folderName":     dirName,
	}
	_, err := d.request("https://cloud.189.cn/api/open/file/createFolder.action", http.MethodPost, func(req *resty.Request) {
		req.SetFormData(form)
	}, nil)
	return err
}

func (d *Cloud189) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	isFolder := 0
	if srcObj.IsDir() {
		isFolder = 1
	}
	taskInfos := []base.Json{
		{
			"fileId":   srcObj.GetID(),
			"fileName": srcObj.GetName(),
			"isFolder": isFolder,
		},
	}
	taskInfosBytes, err := utils.Json.Marshal(taskInfos)
	if err != nil {
		return err
	}
	form := map[string]string{
		"type":           "MOVE",
		"targetFolderId": dstDir.GetID(),
		"taskInfos":      string(taskInfosBytes),
	}
	_, err = d.request("https://cloud.189.cn/api/open/batch/createBatchTask.action", http.MethodPost, func(req *resty.Request) {
		req.SetFormData(form)
	}, nil)
	return err
}

func (d *Cloud189) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	url := "https://cloud.189.cn/api/open/file/renameFile.action"
	idKey := "fileId"
	nameKey := "destFileName"
	if srcObj.IsDir() {
		url = "https://cloud.189.cn/api/open/file/renameFolder.action"
		idKey = "folderId"
		nameKey = "destFolderName"
	}
	form := map[string]string{
		idKey:   srcObj.GetID(),
		nameKey: newName,
	}
	_, err := d.request(url, http.MethodPost, func(req *resty.Request) {
		req.SetFormData(form)
	}, nil)
	return err
}

func (d *Cloud189) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	isFolder := 0
	if srcObj.IsDir() {
		isFolder = 1
	}
	taskInfos := []base.Json{
		{
			"fileId":   srcObj.GetID(),
			"fileName": srcObj.GetName(),
			"isFolder": isFolder,
		},
	}
	taskInfosBytes, err := utils.Json.Marshal(taskInfos)
	if err != nil {
		return err
	}
	form := map[string]string{
		"type":           "COPY",
		"targetFolderId": dstDir.GetID(),
		"taskInfos":      string(taskInfosBytes),
	}
	_, err = d.request("https://cloud.189.cn/api/open/batch/createBatchTask.action", http.MethodPost, func(req *resty.Request) {
		req.SetFormData(form)
	}, nil)
	return err
}

func (d *Cloud189) Remove(ctx context.Context, obj model.Obj) error {
	isFolder := 0
	if obj.IsDir() {
		isFolder = 1
	}
	taskInfos := []base.Json{
		{
			"fileId":   obj.GetID(),
			"fileName": obj.GetName(),
			"isFolder": isFolder,
		},
	}
	taskInfosBytes, err := utils.Json.Marshal(taskInfos)
	if err != nil {
		return err
	}
	form := map[string]string{
		"type":           "DELETE",
		"targetFolderId": "",
		"taskInfos":      string(taskInfosBytes),
	}
	_, err = d.request("https://cloud.189.cn/api/open/batch/createBatchTask.action", http.MethodPost, func(req *resty.Request) {
		req.SetFormData(form)
	}, nil)
	return err
}

func (d *Cloud189) Put(ctx context.Context, dstDir model.Obj, stream model.FileStreamer, up driver.UpdateProgress) error {
	return d.newUpload(ctx, dstDir, stream, up)
}

func (d *Cloud189) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	capacityInfo, err := d.getCapacityInfo(ctx)
	if err != nil {
		return nil, err
	}
	return &model.StorageDetails{
		DiskUsage: model.DiskUsage{
			TotalSpace: capacityInfo.CloudCapacityInfo.TotalSize,
			UsedSpace:  capacityInfo.CloudCapacityInfo.UsedSize,
		},
	}, nil
}

var _ driver.Driver = (*Cloud189)(nil)
