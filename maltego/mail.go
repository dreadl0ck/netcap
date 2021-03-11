/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package maltego

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// MailCountFunc is a function that counts something over multiple Mail audit records.
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type MailCountFunc func()

// MailTransformationFunc is a transformation over Mail audit records.
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type MailTransformationFunc = func(lt maltego.LocalTransform, trx *maltego.Transform, mail *types.Mail, min, max uint64, path string, ip string)

// MailTransform applies a maltego transformation over Mail audit records.
func MailTransform(count MailCountFunc, transform MailTransformationFunc) {
	var (
		lt               = maltego.ParseLocalArguments(os.Args[3:])
		path             = lt.Values["path"]
		ipaddr           = lt.Values[PropertyIpAddr]
		dir              = filepath.Dir(path)
		mailAuditRecords = filepath.Join(dir, "Mail.ncap.gz")
		trx              = maltego.Transform{}
	)

	f, path := openFile(mailAuditRecords)

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		maltego.Die(errUnexpectedFileType, f.Name())
	}

	r := openNetcapArchive(path)

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		maltego.Die("failed to read file header", errFileHeader.Error())
	}

	if header.Type != types.Type_NC_Mail {
		maltego.Die("file does not contain Mail records", header.Type.String())
	}

	var (
		mail = new(types.Mail)
		pm   proto.Message
		ok   bool
	)
	pm = mail

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
		err error
	)

	if count != nil {
		for {
			err = r.Next(mail)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				maltego.Die(err.Error(), errUnexpectedReadFailure)
			}

			count()
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}
	}

	r = openNetcapArchive(path)

	// read netcap header - ignore err as it has been checked before
	_, _ = r.ReadHeader()

	for {
		err = r.Next(mail)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, mail, min, max, path, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

// LoadMails will load the email audit records into memory and return them.
func LoadMails() map[string]*types.Mail {
	var (
		lt    = maltego.ParseLocalArguments(os.Args[3:])
		path  = filepath.Join(filepath.Dir(strings.TrimPrefix(lt.Values["path"], "file://")), "Mail.ncap.gz")
		mails = make(map[string]*types.Mail)
	)

	netio.FPrintBuildInfo(os.Stderr)
	f, path := openFile(path)

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		maltego.Die(errUnexpectedFileType, f.Name())
	}

	r := openNetcapArchive(path)

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		maltego.Die("failed to read file header", errFileHeader.Error())
	}

	if //goland:noinspection GoNilness
	header.Type != types.Type_NC_Mail {
		maltego.Die("file does not contain Mail records", header.Type.String())
	}

	var (
		mail = new(types.Mail)
		pm   proto.Message
		ok   bool
		err  error
	)

	pm = mail

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	for {
		err = r.Next(mail)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		mails[mail.ID] = &types.Mail{
			Timestamp:       mail.Timestamp,
			ReturnPath:      mail.ReturnPath,
			From:            mail.From,
			To:              mail.To,
			CC:              mail.CC,
			Subject:         mail.Subject,
			Date:            mail.Date,
			MessageID:       mail.MessageID,
			References:      mail.References,
			InReplyTo:       mail.InReplyTo,
			ContentLanguage: mail.ContentLanguage,
			HasAttachments:  mail.HasAttachments,
			XOriginatingIP:  mail.XOriginatingIP,
			ContentType:     mail.ContentType,
			EnvelopeTo:      mail.EnvelopeTo,
			Body:            mail.Body,
			ClientIP:        mail.ClientIP,
			ServerIP:        mail.ServerIP,
			ID:              mail.ID,
			DeliveryDate:    mail.DeliveryDate,
			Origin:          mail.Origin,
		}
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	return mails
}
