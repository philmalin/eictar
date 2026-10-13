package archive

import (
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/pipeline"
)

// blockingFile holds each ReadAt until release is closed.
type blockingFile struct {
	archiveFile
	entered chan struct{}
	release chan struct{}
}

func (f *blockingFile) ReadAt(b []byte, off int64) (int, error) {
	select {
	case f.entered <- struct{}{}:
	default:
	}
	<-f.release
	return f.archiveFile.ReadAt(b, off)
}

// TestRecompressOneWaitsForTheDecoder: when the pipeline has failed,
// recompressOne returns only after the decode of the old member has
// stopped. The caller then closes the reader, and a decode that still read
// from it found no file (a panic on NetBSD).
func TestRecompressOneWaitsForTheDecoder(t *testing.T) {
	tree := mutTree(t)
	r, err := OpenWith(mkArchive(t, tree, false, "t"), OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var m format.Member
	for _, x := range r.Members() {
		if x.Path == "t/a.txt" {
			m = x
		}
	}
	bf := &blockingFile{archiveFile: r.f, entered: make(chan struct{}, 1), release: make(chan struct{})}
	r.f = bf

	w, err := Create(filepath.Join(t.TempDir(), "n.ect"), Options{Codec: "zstd"})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	failed := errors.New("the pipeline failed")
	b := pipeline.New(pipeline.Config{Workers: 1, ChunkSize: 4096, Budget: pipeline.NewBudget(1 << 20), Encoder: w.Encoder(),
		Emit: func(*format.Member, io.WriterTo) error { return failed }})
	b.Start()
	defer b.Finish()
	if err := b.AddMeta(format.Member{Path: "d", Type: format.TypeDir}); err != nil {
		t.Fatal(err)
	}
	for b.Err() == nil {
		time.Sleep(time.Millisecond)
	}

	returned := make(chan error, 1)
	go func() { returned <- recompressOne(r, w, b, m, nil) }()
	<-bf.entered // the decoder reads the old member
	select {
	case err := <-returned:
		close(bf.release)
		t.Fatalf("returned (%v) while the decoder still reads", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(bf.release)
	if err := <-returned; !errors.Is(err, failed) {
		t.Errorf("%v, want %v", err, failed)
	}
}
