package plg_image_light

// #cgo CFLAGS: -I./deps/src
// #cgo pkg-config:glib-2.0
// #include "glib-2.0/glib.h"
// #include "libresize.h"
import "C"

import (
	"context"
	. "github.com/mickael-kerjean/filestash/server/common"
	"golang.org/x/sync/semaphore"
	"io"
	"time"
	"unsafe"
)

const (
	ThumbnailTimeout       = 5 * time.Second
	ThumbnailMaxConcurrent = 50
)

var VipsLock = semaphore.NewWeighted(ThumbnailMaxConcurrent)

func CreateThumbnail(t *Transform) (io.ReadCloser, error) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(ThumbnailTimeout))
	defer cancel()
	if err := VipsLock.Acquire(ctx, 1); err != nil {
		return nil, ErrCongestion
	}
	defer VipsLock.Release(1)

	imageChannel := make(chan io.ReadCloser, 1)
	go func() {
		filename := C.CString(t.Input)
		len := C.size_t(0)
		var buffer unsafe.Pointer
		if C.image_resize(filename, &buffer, &len, C.int(t.Size), boolToCInt(t.Crop), C.int(t.Quality), boolToCInt(t.Exif)) != 0 {
			C.free(unsafe.Pointer(filename))
			imageChannel <- nil
			return
		}
		C.free(unsafe.Pointer(filename))
		buf := C.GoBytes(buffer, C.int(len))
		C.g_free(C.gpointer(buffer))
		imageChannel <- NewReadCloserFromBytes(buf)
	}()

	select {
	case img := <-imageChannel:
		if img == nil {
			return nil, ErrNotValid
		}
		return img, nil
	case <-ctx.Done():
		return nil, ErrTimeout
	}
}

func boolToCInt(val bool) C.int {
	if !val {
		return C.int(0)
	}
	return C.int(1)
}
