package evidence

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

var ErrNoMatchingPackets = errors.New("no packets matched the requested selection")

func WriteArchive(ctx context.Context, input string, output io.Writer, selection Selection) (PacketManifest, error) {
	archive := zip.NewWriter(output)
	packets, err := archive.CreateHeader(&zip.FileHeader{Name: "packets.pcapng", Method: zip.Store})
	if err != nil {
		return PacketManifest{}, err
	}
	manifest, err := ExportPackets(ctx, input, packets, selection)
	if err != nil {
		return manifest, err
	}
	if manifest.Selected == 0 {
		return manifest, ErrNoMatchingPackets
	}
	entry, err := archive.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Store})
	if err != nil {
		return manifest, err
	}
	if err := json.NewEncoder(entry).Encode(manifest); err != nil {
		return manifest, err
	}
	if err := archive.Close(); err != nil {
		return manifest, err
	}
	return manifest, ctx.Err()
}

// ArchiveToFile atomically publishes a complete archive without replacing existing work.
func ArchiveToFile(ctx context.Context, input, target string, selection Selection) (PacketManifest, error) {
	file, err := os.CreateTemp(filepath.Dir(target), ".netcap-evidence-*.zip")
	if err != nil {
		return PacketManifest{}, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	manifest, err := WriteArchive(ctx, input, file, selection)
	if err != nil {
		return manifest, err
	}
	if err := file.Sync(); err != nil {
		return manifest, err
	}
	if err := file.Close(); err != nil {
		return manifest, err
	}
	if err := ctx.Err(); err != nil {
		return manifest, err
	}
	if err := os.Link(file.Name(), target); err != nil {
		return manifest, err
	}
	return manifest, nil
}
