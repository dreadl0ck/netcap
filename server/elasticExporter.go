package main

// var (
// 	influxClient client.Client
// 	exportChan   = make(chan *client.Point)
// )

// // Exportable defines an API to export instances to various formats
// type Exportable interface {
// 	Export()
// 	String() string
// 	JSON() string
// 	CSVHeader() []string
// 	CSVRecord() []string
// }

// func initInfluxDBClient() {

// 	var err error

// 	// Create a new HTTPClient
// 	influxClient, err = client.NewHTTPClient(client.HTTPConfig{
// 		Addr:     conf.InfluxEndPoint,
// 		Username: conf.InfluxUser,
// 		Password: conf.InfluxPassword,
// 	})
// 	if err != nil {
// 		Log.Fatal("failed to init influxDB client: ", err)
// 	}
// }

// func printHandler(p *gopacket.Packet, rules *yara.Rules, geodb *maxminddb.Reader) {

// 	// analyze packet
// 	packet := NewPacket(p, rules, geodb)
// 	fmt.Println(packet)

// 	progressChan <- true
// }

// func exportHandler(p *gopacket.Packet, rules *yara.Rules, geodb *maxminddb.Reader) {

// 	// analyze packet
// 	packet := NewPacket(p, rules, geodb)

// 	// export raw packet to influxDB
// 	packet.Export()

// 	// check if its a TCP Packet
// 	if tl := (*p).TransportLayer(); tl != nil {
// 		if tl.LayerType() == layers.LayerTypeTCP {
// 			tcp, ok := tl.(*layers.TCP)
// 			if ok {
// 				switch tcp.DstPort {
// 				// HTTP
// 				case layers.TCPPort(80):
// 					assemblerMutex.Lock()
// 					assembler.AssembleWithTimestamp((*p).NetworkLayer().NetworkFlow(), tcp, time.Unix(0, packet.Timestamp))
// 					assemblerMutex.Unlock()
// 				// HTTPS
// 				case layers.TCPPort(443):
// 					if h, ok := ExtractTLSHandShake(tcp, packet.SourceIP, packet.DestIP); ok {
// 						h.Export()
// 					}
// 				}
// 			}
// 		}
// 	}

// }

// func handleExportDir() {
// 	files, err := ioutil.ReadDir(*flagInput)
// 	if err != nil {
// 		Log.Fatal("failed to read directory: ", err)
// 	}

// 	var path = *flagInput
// 	if !strings.HasSuffix(path, "/") {
// 		path += "/"
// 	}

// 	for _, f := range files {
// 		if filepath.Ext(f.Name()) == ".pcap" {
// 			handleExportFile(path + f.Name())
// 		}
// 	}
// }

// func handleExportFile(path string) {

// 	var start = time.Now()

// 	SourceFile = filepath.Base(path)
// 	AnalysisStart = time.Now().String()

// 	initInfluxDBClient()
// 	go readHTTPFlowChannel()

// 	readPcapFileAsync(path, *flagBPF, exportHandler)

// 	fmt.Println(path+" exported in", time.Since(start))
// 	fmt.Println("")
// }

// func exportRoutine() {

// 	// Create a new point batch
// 	bp, err := client.NewBatchPoints(client.BatchPointsConfig{
// 		Database: "telegraf",
// 	})
// 	if err != nil {
// 		Log.Fatal(err)
// 	}

// 	var (
// 		batchSize = 5000
// 		count     = 0
// 	)

// 	for {
// 		select {
// 		case pt := <-exportChan:
// 			bp.AddPoint(pt)
// 			count++
// 			if count == batchSize || current == total {

// 				Log.Debug("writing batch with ", batchSize, " points")

// 				// Write the batch
// 				if err := influxClient.Write(bp); err != nil {
// 					Log.Fatal(err)
// 				}
// 				// Create a new point batch
// 				bp, err = client.NewBatchPoints(client.BatchPointsConfig{
// 					Database: "telegraf",
// 				})
// 				if err != nil {
// 					Log.Fatal(err)
// 				}
// 				count = 0
// 			}
// 		}
// 	}
// }
