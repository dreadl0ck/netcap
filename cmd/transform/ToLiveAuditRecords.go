package transform

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/utils"
)

func toLiveAuditRecords() {
	// setup logger for io pkg
	ioLog := zap.New(zapcore.NewNopCore())
	defer func() {
		err := ioLog.Sync()
		if err != nil {
			log.Println(err)
		}
	}()

	io.SetLogger(ioLog)

	var (
		lt   = maltego.ParseLocalArguments(os.Args[1:])
		path = getPathLiveCaptureOutDir(lt.Value)
	)

	log.Println("path:", path, "iface", lt.Value)
	writeLiveAuditRecords(path)
}

func writeLiveAuditRecords(outDir string) {
	var allDecoders []string

	// generate entities for audit records
	// *AuditRecords entity and an entity for the actual audit record instance
	decoder.ApplyActionToCustomDecoders(func(d decoder.CustomDecoderAPI) {
		allDecoders = append(allDecoders, d.GetName())
	})

	decoder.ApplyActionToGoPacketDecoders(func(e *decoder.GoPacketDecoder) {
		name := strings.ReplaceAll(e.Layer.String(), "/", "")
		allDecoders = append(allDecoders, name)
	})

	// generate maltego transform
	trx := maltego.Transform{}
	for _, name := range allDecoders {
		path := filepath.Join(outDir, name+defaults.FileExtension)

		// stat generated profiles
		stat, err := os.Stat(path)
		if err != nil {
			log.Println("invalid path:", err, "trying", defaults.FileExtensionCompressed, "extension")

			path = filepath.Join(outDir, name+defaults.FileExtensionCompressed)
			stat, err = os.Stat(path)
			if err != nil {
				log.Println("invalid path:", err)
				continue
			}
		}
		if stat.IsDir() {
			log.Println("not a file: ", err)

			continue
		}

		// TODO: return structure from collect invocation
		// that contains the number of records per type
		// to avoid opening the file again
		numRecords, errCount := io.Count(path)
		if errCount != nil {
			log.Println("failed to count audit records:", errCount)

			continue
		}

		if numRecords == 0 {
			log.Println("no records in", path)
			continue
		}

		ent := trx.AddEntityWithPath("netcap."+name+"AuditRecords", utils.Pluralize(name), path)
		ent.AddProperty("description", "Description", maltego.Loose, name+defaults.FileExtension)
		ent.SetLinkLabel(strconv.Itoa(int(numRecords)))

		// add notes for specific audit records here
		switch name {
		//case "DeviceProfile":
		//	di := "<h3>Device Profile</h3><p>Timestamp: " + time.Now().UTC().String() + "</p>"
		//	ent.AddDisplayInformation(di, "Netcap Info")
		//
		//	num, errCountRecords := io.Count(path)
		//	if errCountRecords != nil {
		//		log.Println("failed to count audit records:", errCountRecords)
		//	}
		//
		//	ent.SetNote("Storage Path: " + outDir + "\nFile Size: " + humanize.Bytes(uint64(stat.Size())) + "\nNum Profiles: " + strconv.FormatInt(num, 10) + "\nInterface: " + iface + "\nStart Time: " + start.String())
		}
	}

	time.Sleep(200 * time.Millisecond)

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
