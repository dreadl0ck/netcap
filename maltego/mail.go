package maltego

import (
	"errors"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"io"
	"log"
	"os"
	"strings"
)

// LoadMails will load the email audit records into memory and return them.
func LoadMails() map[string]*types.Mail {

	lt := ParseLocalArguments(os.Args[1:])
	profilesFile := lt.Values["path"]

	mails := make(map[string]*types.Mail)
	stdOut := os.Stdout
	os.Stdout = os.Stderr

	f, err := os.Open(profilesFile)
	if err != nil {
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		log.Fatal("input file must be an audit record file")
	}

	os.Stdout = stdOut

	r, err := netio.Open(profilesFile, defaults.BufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		log.Fatal(errFileHeader)
	}

	if header.Type != types.Type_NC_DeviceProfile {
		panic("file does not contain DeviceProfile records: " + header.Type.String())
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
