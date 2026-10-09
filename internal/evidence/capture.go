package evidence

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type CaptureConfig struct {
	Source          string `json:"source"`
	Kind            string `json:"kind"`
	BPF             string `json:"bpf"`
	SnapLen         int    `json:"snapLen"`
	Workers         int    `json:"workers"`
	IncludeDecoders string `json:"includeDecoders"`
	ExcludeDecoders string `json:"excludeDecoders"`
	Reassembly      bool   `json:"reassembly"`
	RetainPackets   bool   `json:"retainPackets"`
	SegmentBytes    int64  `json:"segmentBytes,string"`
	RetentionBytes  int64  `json:"retentionBytes,string"`
}

type CaptureSegment struct {
	Name         string `json:"name"`
	Bytes        int64  `json:"bytes,string"`
	Packets      uint64 `json:"packets"`
	FirstOrdinal uint64 `json:"firstOrdinal"`
	LastOrdinal  uint64 `json:"lastOrdinal"`
	FirstNs      string `json:"firstNs"`
	LastNs       string `json:"lastNs"`
	SHA256       string `json:"sha256"`
	State        string `json:"state"`
}

type CaptureManifest struct {
	CommunityScopes  *ScopeLedger     `json:"communityScopes,omitempty"`
	Version          int              `json:"version"`
	RunID            string           `json:"runId"`
	CreatedAt        string           `json:"createdAt"`
	Status           string           `json:"status"`
	Error            string           `json:"error,omitempty"`
	Config           CaptureConfig    `json:"config"`
	ConfigSHA256     string           `json:"configSHA256"`
	InputSHA256      string           `json:"inputSHA256,omitempty"`
	IngressPackets   uint64           `json:"ingressPackets"`
	AdmittedPackets  uint64           `json:"admittedPackets"`
	QueueDrops       uint64           `json:"queueDrops"`
	CapturedBytes    uint64           `json:"capturedBytes,string"`
	WireBytes        uint64           `json:"wireBytes,string"`
	TruncatedPackets uint64           `json:"truncatedPackets"`
	FirstNs          *int64           `json:"firstNs,omitempty,string"`
	LastNs           *int64           `json:"lastNs,omitempty,string"`
	KernelReceived   *uint64          `json:"kernelReceived"`
	KernelDrops      *uint64          `json:"kernelDrops"`
	KernelStatsError string           `json:"kernelStatsError,omitempty"`
	Segments         []CaptureSegment `json:"segments"`
	Limitations      []string         `json:"limitations"`
}

type Capture struct {
	scopes        map[string]CommunityScope
	scopeOverflow uint64
	mu            sync.Mutex
	directory     string
	manifest      CaptureManifest
	writer        *pcapgo.NgWriter
	file          *os.File
	interfaces    map[captureInterface]int
	segment       *CaptureSegment
	sequence      uint64
	storageError  error
	closed        bool
	sourceInfo    os.FileInfo
}

type captureInterface struct {
	index int
	link  layers.LinkType
}

func NewCapture(ctx context.Context, directory string, config CaptureConfig) (*Capture, error) {
	if config.Kind != "file" && config.Kind != "live" {
		return nil, fmt.Errorf("capture kind must be file or live")
	}
	if config.RetainPackets && (config.SegmentBytes < 1<<20 || config.RetentionBytes < config.SegmentBytes) {
		return nil, fmt.Errorf("retention requires segment >=1 MiB and retention >=segment")
	}
	path := filepath.Join(directory, "capture-manifest.json")
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("capture manifest already exists; use a fresh output directory")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	configuration, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(configuration)
	c := &Capture{directory: directory, manifest: CaptureManifest{Version: 1, RunID: hex.EncodeToString(id[:]), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: "running", Config: config, ConfigSHA256: hex.EncodeToString(hash[:]), Segments: []CaptureSegment{}, Limitations: []string{
		"capture timestamps use source clock; no clock-skew correction is inferred",
		"capture-point topology, NAT and encryption visibility require external context",
		"kernel counters are unavailable unless reported; null does not mean zero",
		"retained derivatives preserve packet bytes and timestamps but do not copy original interface options or secrets",
	}}}
	if config.Kind == "file" {
		file, err := os.Open(config.Source)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		before, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if !before.Mode().IsRegular() {
			return nil, fmt.Errorf("input must be a regular file")
		}
		digest := sha256.New()
		buffer := make([]byte, 1<<20)
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			n, err := file.Read(buffer)
			if n > 0 {
				_, _ = digest.Write(buffer[:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
		}
		after, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return nil, fmt.Errorf("input changed during hashing")
		}
		c.manifest.InputSHA256 = hex.EncodeToString(digest.Sum(nil))
		c.sourceInfo = after
	}
	if err := c.checkpoint(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Capture) Observe(data []byte, ci gopacket.CaptureInfo, linkType layers.LinkType) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("capture manifest closed")
	}
	ordinal := c.manifest.IngressPackets
	c.manifest.IngressPackets++
	c.manifest.CapturedBytes += uint64(len(data))
	if ci.Length > 0 {
		c.manifest.WireBytes += uint64(ci.Length)
	}
	if ci.Length > ci.CaptureLength {
		c.manifest.TruncatedPackets++
	}
	ns := ci.Timestamp.UnixNano()
	if c.manifest.FirstNs == nil || ns < *c.manifest.FirstNs {
		value := ns
		c.manifest.FirstNs = &value
	}
	if c.manifest.LastNs == nil || ns > *c.manifest.LastNs {
		value := ns
		c.manifest.LastNs = &value
	}
	if !c.manifest.Config.RetainPackets {
		return nil
	}
	if int64(len(data))+512 > c.manifest.Config.SegmentBytes {
		c.storageError = fmt.Errorf("captured packet exceeds retention segment capacity")
		return c.storageError
	}
	if len(c.manifest.Segments) >= 100000 {
		c.storageError = fmt.Errorf("retention segment history limit exceeded")
		return c.storageError
	}
	if c.storageError != nil {
		return c.storageError
	}
	if c.segment != nil && c.segment.Bytes+int64(len(data))+128 > c.manifest.Config.SegmentBytes {
		if err := c.finishSegment(); err != nil {
			c.storageError = err
			return err
		}
	}
	if c.writer == nil {
		if err := c.expireSegments(c.manifest.Config.RetentionBytes - c.manifest.Config.SegmentBytes); err != nil {
			c.storageError = err
			return err
		}
		root := filepath.Join(c.directory, "retained-packets")
		if err := os.MkdirAll(root, 0700); err != nil {
			c.storageError = err
			return err
		}
		name := fmt.Sprintf("segment-%06d.pcapng", c.sequence)
		c.sequence++
		file, err := os.OpenFile(filepath.Join(root, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			c.storageError = err
			return err
		}
		writer, err := pcapgo.NewNgWriter(file, linkType)
		if err != nil {
			file.Close()
			c.storageError = err
			return err
		}
		c.file, c.writer, c.interfaces = file, writer, map[captureInterface]int{{ci.InterfaceIndex, linkType}: 0}
		c.segment = &CaptureSegment{Name: filepath.Join("retained-packets", name), State: "open", Bytes: 512, FirstOrdinal: ordinal, FirstNs: fmt.Sprint(ns)}
	}
	key := captureInterface{ci.InterfaceIndex, linkType}
	index, ok := c.interfaces[key]
	if !ok {
		if len(c.interfaces) >= 1024 {
			c.storageError = fmt.Errorf("retention interface limit exceeded")
			return c.storageError
		}
		intf := pcapgo.DefaultNgInterface
		intf.LinkType = linkType
		var err error
		index, err = c.writer.AddInterface(intf)
		if err != nil {
			c.storageError = err
			return err
		}
		c.interfaces[key] = index
	}
	ci.InterfaceIndex = index
	ci.CaptureLength = len(data)
	if err := c.writer.WritePacket(ci, data); err != nil {
		c.storageError = err
		return err
	}
	c.segment.Bytes += int64(len(data)) + 128
	c.segment.Packets++
	c.segment.LastOrdinal = ordinal
	c.segment.LastNs = fmt.Sprint(ns)
	return nil
}

func (c *Capture) Checkpoint(admitted, drops uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.manifest.AdmittedPackets, c.manifest.QueueDrops = admitted, drops
	return c.checkpoint()
}
func (c *Capture) Kernel(received, dropped *uint64, statsError string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if received != nil {
		value := *received
		c.manifest.KernelReceived = &value
	}
	if dropped != nil {
		value := *dropped
		c.manifest.KernelDrops = &value
	}
	c.manifest.KernelStatsError = statsError
}

func (c *Capture) Close(status string, admitted, drops uint64, captureError error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.storageError
	}
	c.closed = true
	if c.sourceInfo != nil {
		now, err := os.Stat(c.manifest.Config.Source)
		if err != nil || !os.SameFile(c.sourceInfo, now) || c.sourceInfo.Size() != now.Size() || !c.sourceInfo.ModTime().Equal(now.ModTime()) {
			c.storageError = fmt.Errorf("capture input changed or disappeared during analysis")
		}
	}
	if err := c.finishSegment(); err != nil {
		c.storageError = err
	}
	c.manifest.AdmittedPackets, c.manifest.QueueDrops = admitted, drops
	c.manifest.Status = status
	if captureError != nil {
		c.manifest.Status = "error"
		c.manifest.Error = captureError.Error()
	}
	if c.storageError != nil {
		c.manifest.Status = "error"
		c.manifest.Error = c.storageError.Error()
	}
	if c.manifest.Status == "done" && (drops > 0 || c.manifest.TruncatedPackets > 0 || (c.manifest.KernelDrops != nil && *c.manifest.KernelDrops > 0)) {
		c.manifest.Status = "partial"
	}
	if err := c.checkpoint(); err != nil {
		return err
	}
	return c.storageError
}

func (c *Capture) finishSegment() error {
	if c.writer == nil {
		return nil
	}
	defer c.file.Close()
	if err := c.writer.Flush(); err != nil {
		return err
	}
	if err := c.file.Sync(); err != nil {
		return err
	}
	if err := c.file.Close(); err != nil {
		return err
	}
	path := filepath.Join(c.directory, c.segment.Name)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	digest := sha256.New()
	_, err = io.Copy(digest, file)
	file.Close()
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	c.segment.Bytes = info.Size()
	c.segment.SHA256 = hex.EncodeToString(digest.Sum(nil))
	c.segment.State = "retained"
	c.manifest.Segments = append(c.manifest.Segments, *c.segment)
	c.writer, c.file, c.segment = nil, nil, nil
	if err := c.expireSegments(c.manifest.Config.RetentionBytes); err != nil {
		return err
	}
	return c.checkpoint()
}

func (c *Capture) expireSegments(budget int64) error {
	var total int64
	for _, segment := range c.manifest.Segments {
		if segment.State == "retained" {
			total += segment.Bytes
		}
	}
	for i := range c.manifest.Segments {
		segment := &c.manifest.Segments[i]
		if total <= budget {
			break
		}
		if segment.State == "retained" {
			if err := os.Remove(filepath.Join(c.directory, segment.Name)); err != nil {
				return err
			}
			total -= segment.Bytes
			segment.State = "expired"
		}
	}
	return nil
}

func (c *Capture) checkpoint() error {
	manifest := c.manifest
	scopes := c.scopeSnapshot()
	manifest.CommunityScopes = &scopes
	if c.segment != nil {
		manifest.Segments = append(append([]CaptureSegment(nil), manifest.Segments...), *c.segment)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(c.directory, ".capture-manifest-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(c.directory, "capture-manifest.json"))
}
