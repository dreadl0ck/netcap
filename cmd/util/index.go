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

package util

import (
	"bufio"
	"fmt"
	"github.com/blevesearch/bleve"
	"log"
	"os"
	"strings"
)

type Exploit struct {
	Id          string
	Status      string
	Description string
}

func indexData() {

	indexName := "/usr/local/etc/netcap/dbs/cve.bleve"

	index := makeBleveIndex(indexName) // To create a new index
	//index, _ := bleve.Open(indexName) // To search or update an existing index

	file, err := os.Open("allitems.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		lineSlice := strings.Split(line, ",")
		lineExploit := Exploit{
			Id:          lineSlice[0],
			Status:      lineSlice[1],
			Description: lineSlice[2],
		}
		index.Index(lineExploit.Id, lineExploit)
	}

	fmt.Println("Loaded DB")

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func makeBleveIndex(indexName string) bleve.Index {
	mapping := bleve.NewIndexMapping()
	index, err := bleve.New(indexName, mapping)
	if err != nil {
		log.Fatalln("Trouble making index!")
	}
	return index
}
