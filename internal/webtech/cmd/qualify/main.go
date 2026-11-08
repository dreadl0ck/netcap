package main

import (
	"encoding/json"
	"fmt"
	"github.com/dreadl0ck/netcap/internal/webtech"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		panic("qualify VECTORS CATALOGUE")
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var cases []struct {
		Body, Method, State string
		Status              int
		Generator           []string
		ContentType         string `json:"content_type"`
	}
	if err = json.Unmarshal(b, &cases); err != nil {
		panic(err)
	}
	b, err = os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	e, err := webtech.Parse(b)
	if err != nil {
		panic(err)
	}
	results := []webtech.Report{}
	for _, c := range cases {
		if c.Method == "" {
			c.Method = "GET"
		}
		if c.Status == 0 {
			c.Status = 200
		}
		if c.State == "" {
			c.State = "complete"
		}
		if c.ContentType == "" {
			c.ContentType = "text/html"
		}
		results = append(results, e.Observe(webtech.Observation{Method: c.Method, Status: c.Status, Body: []byte(c.Body), Generator: c.Generator, BodyState: c.State, ContentType: c.ContentType}))
	}
	out, err := json.Marshal(results)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
