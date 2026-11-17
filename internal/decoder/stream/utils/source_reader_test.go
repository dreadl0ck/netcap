package utils

import (
	"bufio"
	"errors"
	"io"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func TestSourceRangeReaderReleasesBudgetOnFailureAndPanic(t *testing.T) {
	source := core.SliceSource{&core.StreamData{SkippedBytes: 3}, &core.StreamData{RawData: []byte("line\n")}}
	budget, _ := core.NewStateBudget(8192, nil)
	c := &core.ConversationInfo{StateBudget: budget}
	if err := WithSourceReader(c, source, false, 4096, func(reader *bufio.Reader, _ *ReadPosition) error {
		line, err := reader.ReadString('\n')
		if line != "line\n" {
			t.Fatal(line)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if budget.Health().RetainedBytes != 0 {
		t.Fatal("source reader retained credits", budget.Health())
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("consumer panic disappeared")
			}
		}()
		_ = WithSourceReader(c, source, false, 4096, func(*bufio.Reader, *ReadPosition) error { panic("control") })
	}()
	if budget.Health().RetainedBytes != 0 {
		t.Fatal("panicking reader retained credits", budget.Health())
	}
	if err := WithSourceReader(c, source, false, 16384, func(*bufio.Reader, *ReadPosition) error { return io.EOF }); !errors.Is(err, core.ErrStreamStateBudget) || !errors.Is(c.FragmentError, core.ErrStreamStateBudget) {
		t.Fatal("reader allocation bypassed budget", err, c.FragmentError)
	}
}
