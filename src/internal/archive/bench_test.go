package archive

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// benchTree is a mixed corpus of about 64 MiB: many small text files, some
// large compressible files, and incompressible data, which is roughly what a
// home directory holds.
func benchTree(b *testing.B) (*testutil.Tree, int64) {
	b.Helper()
	tree := testutil.NewTree(b)
	rnd := rand.New(rand.NewSource(7))
	words := strings.Fields("the quick brown fox jumps over a lazy dog while archive chunk index member codec")
	text := func(n int) []byte {
		var sb strings.Builder
		for sb.Len() < n {
			sb.WriteString(words[rnd.Intn(len(words))])
			sb.WriteByte(' ')
		}
		return []byte(sb.String()[:n])
	}
	var total int64
	for i := 0; i < 2000; i++ { // 2000 small files, 16 MiB
		tree.File(fmt.Sprintf("small/%02d/f%04d.txt", i%50, i), 0o644, text(8<<10))
		total += 8 << 10
	}
	for i := 0; i < 4; i++ { // 4 large text files, 32 MiB
		tree.File(fmt.Sprintf("large/t%d.txt", i), 0o644, text(8<<20))
		total += 8 << 20
	}
	for i := 0; i < 2; i++ { // 2 incompressible files, 16 MiB
		buf := make([]byte, 8<<20)
		rnd.Read(buf)
		tree.File(fmt.Sprintf("random/r%d.bin", i), 0o644, buf)
		total += 8 << 20
	}
	return tree, total
}

var benchCodecs = []string{"none", "zstd", "zstd:level=19", "gzip", "s2", "xz"}

// BenchmarkCreate reports create throughput for each codec, in plaintext
// bytes per second.
//
//	make bench
func BenchmarkCreate(b *testing.B) {
	tree, total := benchTree(b)
	for _, spec := range benchCodecs {
		name, params := splitSpec(spec)
		b.Run(spec, func(b *testing.B) {
			b.SetBytes(total)
			for i := 0; i < b.N; i++ {
				archive := filepath.Join(b.TempDir(), "b.ect")
				if _, err := CreateArchive(CreateConfig{
					Archive: archive, Paths: []string{"small", "large", "random"}, BaseDir: tree.Root,
					Options: Options{Codec: name, Params: params},
				}); err != nil {
					b.Fatal(err)
				}
				if i == 0 {
					b.ReportMetric(float64(mustStat(b, archive).Size())/float64(total), "ratio")
				}
			}
		})
	}
}

// BenchmarkExtract reports extraction throughput for each codec.
func BenchmarkExtract(b *testing.B) {
	tree, total := benchTree(b)
	for _, spec := range benchCodecs {
		name, params := splitSpec(spec)
		archive := filepath.Join(b.TempDir(), "b.ect")
		if _, err := CreateArchive(CreateConfig{
			Archive: archive, Paths: []string{"small", "large", "random"}, BaseDir: tree.Root,
			Options: Options{Codec: name, Params: params},
		}); err != nil {
			b.Fatal(err)
		}
		b.Run(spec, func(b *testing.B) {
			b.SetBytes(total)
			for i := 0; i < b.N; i++ {
				if _, err := Extract(ExtractConfig{Archive: archive, Destination: b.TempDir()}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func splitSpec(spec string) (string, codec.Params) {
	name, rest, ok := strings.Cut(spec, ":")
	if !ok {
		return name, nil
	}
	k, v, _ := strings.Cut(rest, "=")
	return name, codec.Params{k: v}
}
