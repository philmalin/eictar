package archive

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"runtime/pprof"
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

// smallTree is 20000 source-like files of 0.5 to 6 KiB, which is the case
// where the setup of a decoder for each member costs the most, compared with
// the decode (doc/design.md 15.2).
func smallTree(b *testing.B) (*testutil.Tree, int64) {
	b.Helper()
	tree := testutil.NewTree(b)
	rnd := rand.New(rand.NewSource(11))
	var total int64
	for i := 0; i < 20000; i++ {
		var sb strings.Builder
		sb.WriteString("// Copyright 2026 The Example Authors. All rights reserved.\n\n")
		fmt.Fprintf(&sb, "package pkg%d\n\nimport (\n\t\"fmt\"\n\t\"io\"\n)\n\n", i%40)
		for j := 0; j < 2+rnd.Intn(30); j++ {
			fmt.Fprintf(&sb, "func helper%d_%d(w io.Writer, s string) error {\n\t_, err := fmt.Fprintf(w, \"%%s %d\\n\", s)\n\treturn err\n}\n\n", i, j, rnd.Intn(1000))
		}
		tree.File(fmt.Sprintf("src/%03d/f%05d.go", i%200, i), 0o644, []byte(sb.String()))
		total += int64(sb.Len())
	}
	return tree, total
}

// BenchmarkSmallFiles reports verify and extract throughput on many small
// files, for one worker and for many.
//
//	go test -run - -bench SmallFiles ./src/internal/archive/
func BenchmarkSmallFiles(b *testing.B) {
	tree, total := smallTree(b)
	for _, tc := range []struct {
		spec      string
		encrypted bool
	}{
		{"zstd", false}, {"zstd:train=on", false}, {"zstd", true}, {"s2", false},
	} {
		name, params := splitSpec(tc.spec)
		cfg := CreateConfig{
			Archive: filepath.Join(b.TempDir(), "s.ect"), Paths: []string{"src"}, BaseDir: tree.Root,
			Options: Options{Codec: name, Params: params},
		}
		var open OpenOptions
		label := tc.spec
		if tc.encrypted {
			cfg.Encryption = &EncryptionConfig{Passphrase: []byte("correct horse"), Params: testKDF}
			open = OpenOptions{Passphrase: passphrase("correct horse")}
			label += "+enc"
		}
		if _, err := CreateArchive(cfg); err != nil {
			b.Fatal(err)
		}
		// Each timed loop carries a pprof label, which its workers inherit,
		// so that -cpuprofile can leave out the creation of the archives:
		//	go tool pprof -tagfocus bench=verify/zstd/j24 ...
		loop := func(b *testing.B, bench string, body func() error) {
			b.SetBytes(total)
			pprof.Do(context.Background(), pprof.Labels("bench", bench), func(context.Context) {
				for b.Loop() {
					if err := body(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
		bench := "open/" + label
		b.Run(bench, func(b *testing.B) {
			loop(b, bench, func() error {
				r, err := OpenWith(cfg.Archive, open)
				if err == nil {
					r.Close()
				}
				return err
			})
		})
		for _, workers := range []int{1, 24} {
			bench := fmt.Sprintf("verify/%s/j%d", label, workers)
			b.Run(bench, func(b *testing.B) {
				loop(b, bench, func() error {
					_, err := VerifyArchive(VerifyConfig{Archive: cfg.Archive, Open: open, Workers: workers})
					return err
				})
			})
		}
		bench = "extract/" + label + "/j24"
		b.Run(bench, func(b *testing.B) {
			loop(b, bench, func() error {
				_, err := Extract(ExtractConfig{Archive: cfg.Archive, Passphrase: open.Passphrase, Destination: b.TempDir(), Workers: 24})
				return err
			})
		})
	}
}
