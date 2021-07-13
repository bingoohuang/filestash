package model

/*
 * Implementation of a webdav.FileSystem: https://godoc.org/golang.org/x/net/webdav#FileSystem that is used
 * to generate our webdav server.
 * A lot of memoization is happening so that we don't DDOS the underlying storage which was important
 * considering most webdav client within OS are extremely greedy in HTTP request
 */

import (
	"context"
	"fmt"
	. "github.com/mickael-kerjean/filestash/server/common"
	"github.com/mickael-kerjean/net/webdav"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DAVCachePath = "data/cache/webdav/"

var (
	cachePath   string
	webdavCache AppCache
)

func init() {
	cachePath = filepath.Join(GetCurrentDir(), DAVCachePath) + "/"
	os.RemoveAll(cachePath)
	os.MkdirAll(cachePath, os.ModePerm)

	webdavCache = NewQuickCache(20, 10)
	webdavCache.OnEvict(func(filename string, _ interface{}) {
		os.Remove(filename)
	})
}

type WebdavFs struct {
	req        *http.Request
	backend    IBackend
	path       string
	id         string
	chroot     string
	webdavFile *WebdavFile
}

func NewWebdavFs(b IBackend, primaryKey string, chroot string, req *http.Request) *WebdavFs {
	return &WebdavFs{
		backend: b,
		id:      primaryKey,
		chroot:  chroot,
		req:     req,
	}
}

func (f WebdavFs) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	if name = f.fullpath(name); name == "" {
		return os.ErrNotExist
	}
	return f.backend.Mkdir(name)
}

func (f *WebdavFs) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	cachePath := fmt.Sprintf("%stmp_%s", cachePath, Hash(f.id+name, 20))
	fwriteFile := func() *os.File {
		if f.req.Method == "PUT" {
			f, err := os.OpenFile(cachePath+"_writer", os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.ModePerm)
			if err != nil {
				return nil
			}
			return f
		}
		return nil
	}
	if f.webdavFile != nil {
		f.webdavFile.fwrite = fwriteFile()
		return f.webdavFile, nil
	}
	if name = f.fullpath(name); name == "" {
		return nil, os.ErrNotExist
	}
	f.webdavFile = &WebdavFile{
		path:    name,
		backend: f.backend,
		cache:   cachePath,
		fwrite:  fwriteFile(),
	}
	return f.webdavFile, nil
}

func (f WebdavFs) RemoveAll(ctx context.Context, name string) error {
	if name = f.fullpath(name); name == "" {
		return os.ErrNotExist
	}
	return f.backend.Rm(name)
}

func (f WebdavFs) Rename(ctx context.Context, oldName, newName string) error {
	if oldName = f.fullpath(oldName); oldName == "" {
		return os.ErrNotExist
	} else if newName = f.fullpath(newName); newName == "" {
		return os.ErrNotExist
	}
	return f.backend.Mv(oldName, newName)
}

func (f *WebdavFs) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	if f.webdavFile != nil {
		f.webdavFile.pushToRemoteIfNeeded()
		return f.webdavFile.Stat()
	}
	fullname := f.fullpath(name)
	if fullname == "" {
		return nil, os.ErrNotExist
	}
	f.webdavFile = &WebdavFile{
		path:    fullname,
		backend: f.backend,
		cache:   fmt.Sprintf("%stmp_%s", cachePath, Hash(f.id+name, 20)),
	}
	return f.webdavFile.Stat()
}

func (f WebdavFs) fullpath(path string) string {
	p := filepath.Join(f.chroot, path)
	if strings.HasSuffix(path, "/") && !strings.HasSuffix(p, "/") {
		p += "/"
	}
	if !strings.HasPrefix(p, f.chroot) {
		return ""
	}
	return p
}

// WebdavFile Implement a webdav.File and os.Stat : https://godoc.org/golang.org/x/net/webdav#File
type WebdavFile struct {
	path    string
	backend IBackend
	cache   string
	fread   *os.File
	fwrite  *os.File
	files   []os.FileInfo
}

func (f *WebdavFile) Read(p []byte) (n int, err error) {
	if strings.HasPrefix(filepath.Base(f.path), ".") {
		return 0, os.ErrNotExist
	}
	if f.fread == nil {
		if f.fread = f.pullRemoteFile(); f.fread == nil {
			return -1, os.ErrInvalid
		}
	}
	return f.fread.Read(p)
}

func (f *WebdavFile) Close() error {
	if f.fread != nil {
		if f.fread.Close() == nil {
			f.fread = nil
		}
	}
	if f.fwrite != nil {
		if err := f.pushToRemoteIfNeeded(); err == nil {
			if f.fwrite.Close() == nil {
				f.fwrite = nil
			}
		}
	}
	return nil
}

func (f *WebdavFile) Seek(offset int64, whence int) (int64, error) {
	if f.fread == nil {
		f.fread = f.pullRemoteFile()
		if f.fread == nil {
			return offset, ErrNotFound
		}
	}
	a, err := f.fread.Seek(offset, whence)
	if err != nil {
		return a, ErrNotFound
	}
	return a, nil
}

func (f *WebdavFile) Readdir(count int) ([]os.FileInfo, error) {
	if f.files != nil {
		return f.files, nil
	}
	if strings.HasPrefix(filepath.Base(f.path), ".") {
		return nil, os.ErrNotExist
	}
	ls, err := f.backend.Ls(f.path)
	f.files = ls
	return ls, err
}

func (f *WebdavFile) Stat() (os.FileInfo, error) {
	f.pushToRemoteIfNeeded()
	if strings.HasSuffix(f.path, "/") {
		_, err := f.Readdir(0)
		if err != nil {
			return nil, os.ErrNotExist
		}
		return f, nil
	}
	baseDir := filepath.Base(f.path)
	files, err := f.backend.Ls(strings.TrimSuffix(f.path, baseDir))
	if err != nil {
		return nil, os.ErrNotExist
	}
	found := false
	for i := range files {
		if files[i].Name() == baseDir {
			found = true
			break
		}
	}
	if !found {
		return nil, os.ErrNotExist
	}
	return f, nil
}

func (f *WebdavFile) Write(p []byte) (int, error) {
	if f.fwrite == nil {
		return 0, os.ErrNotExist
	}
	if strings.HasPrefix(filepath.Base(f.path), ".") {
		return 0, os.ErrNotExist
	}
	return f.fwrite.Write(p)
}

func (f WebdavFile) pullRemoteFile() *os.File {
	filename := f.cache + "_reader"
	if f, err := os.OpenFile(filename, os.O_RDONLY, os.ModePerm); err == nil {
		return f
	}
	if fi, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.ModePerm); err == nil {
		if reader, err := f.backend.Cat(f.path); err == nil {
			io.Copy(fi, reader)
			f.Close()
			webdavCache.SetKey(f.cache+"_reader", nil)
			reader.Close()
			if fi, err = os.OpenFile(filename, os.O_RDONLY, os.ModePerm); err == nil {
				return fi
			}
			return nil
		}
		f.Close()
	}
	return nil
}

func (f *WebdavFile) pushToRemoteIfNeeded() error {
	if f.fwrite == nil {
		return nil
	}
	f.fwrite.Close()
	fi, err := os.OpenFile(f.cache+"_writer", os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
	}
	err = f.backend.Save(f.path, fi)
	if err == nil {
		if err = os.Rename(f.cache+"_writer", f.cache+"_reader"); err == nil {
			f.fwrite = nil
			webdavCache.SetKey(f.cache+"_reader", nil)
		}
	}
	f.Close()
	return err
}

func (f WebdavFile) Name() string {
	return filepath.Base(f.path)
}

func (f *WebdavFile) Size() int64 {
	if f.fread == nil {
		if f.fread = f.pullRemoteFile(); f.fread == nil {
			return 0
		}
	}
	if info, err := f.fread.Stat(); err == nil {
		return info.Size()
	}
	return 0
}

func (f WebdavFile) Mode() os.FileMode {
	return 0
}

func (f WebdavFile) ModTime() time.Time {
	return time.Now()
}
func (f WebdavFile) IsDir() bool {
	if strings.HasSuffix(f.path, "/") {
		return true
	}
	return false
}

func (f WebdavFile) Sys() interface{} {
	return nil
}

func (f WebdavFile) ETag(ctx context.Context) (string, error) {
	// Building an etag can be an expensive call if the data isn't available locally.
	// => 2 etags strategies:
	// - use a legit etag value when the data is already in our cache
	// - use a dummy value that's changing all the time when we don't have much info

	etag := Hash(fmt.Sprintf("%d%s", f.ModTime().UnixNano(), f.path), 20)
	if f.fread != nil {
		if s, err := f.fread.Stat(); err == nil {
			etag = Hash(fmt.Sprintf(`"%x%x"`, f.path, s.Size()), 20)
		}
	}
	return etag, nil
}

var lock webdav.LockSystem

func NewWebdavLock() webdav.LockSystem {
	if lock == nil {
		lock = webdav.NewMemLS()
	}
	return lock
}
