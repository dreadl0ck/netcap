//go:build !appstore

package webui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"testing"
)

// Execute the emitted JS with chart/DOM spies, without installing a browser or
// rebuilding frontend assets. This verifies patches, not browser rendering.
func TestPresentationRuntimeValidatesMessagesAndPreservesInteraction(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node unavailable for emitted JavaScript contract test")
	}
	document := presentChartHTML([]byte("<html><head></head><body></body></html>"), chartPresentation{Presentation: Presentation{Theme: "dark", Locale: "en"}})
	script := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindSubmatch(document)[1]
	request := httptest.NewRequest("GET", "/api/visualize/treemap?theme=light&locale=de", nil)
	dir := t.TempDir()
	var documents []string
	for _, render := range []func(io.Writer) error{
		generateConnectionsProtocolsChart([]ConnectionSummary{{}, {TransportProto: "Requests"}}, true).Render,
		generateDevicesMACVendorsChart(dir, true).Render,
		generateDevicesHardwareChart(dir, true).Render,
		generateDevicesOperatingSystemsChart(dir, true).Render,
		generateDevicesApplicationsChart(dir, true).Render,
		generateDevicesTrafficDistributionChart(dir, true).Render,
		generateSoftwareVersionsChart(dir, true).Render,
		generateTreemapChart(dir, true).Render,
		generateBar3DChart(dir, true).Render,
		generateGraphChart(dir, true, "circular").Render,
		generateGeoChart(dir, true).Render,
		generateHostsGraph(dir, true, 10, "circular").Render,
	} {
		doc, err := injectFullHeightCSSForRequest(render, request)
		if err != nil {
			t.Fatal(err)
		}
		documents = append(documents, string(doc))
	}
	wc := NewChartGenerator("HTTP", "RequestHeader.Requests", "wordcloud", "", true, 10, Presentation{Theme: "light", Locale: "de"}).generateWordCloudChart([]kvPair{{key: "Requests", value: 1}})
	wordCloudDocument, err := io.ReadAll(wc)
	if err != nil {
		t.Fatal(err)
	}
	documents = append(documents, string(wordCloudDocument))
	input, _ := json.Marshal(map[string]any{"script": string(script), "documents": documents})
	command := exec.Command(node, "-e", presentationRuntimeTestJS)
	command.Stdin = bytes.NewReader(input)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("emitted JS contract failed: %v\n%s", err, output)
	}
}

const presentationRuntimeTestJS = `
const assert=require('node:assert/strict'),vm=require('node:vm'),input=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
const listeners={},root={dataset:{},style:{setProperty(){}}},coverage={textContent:''},parent={};
const document={referrer:'https://netcap.test/app',documentElement:root,getElementById(){return null},querySelector(){return null},querySelectorAll(s){return s==='[data-netcap-coverage]'?[coverage]:[]}};
const window={parent,addEventListener(name,fn){listeners[name]=fn}};
const context={window,document,URL,Intl,TextDecoder,atob};vm.createContext(context);vm.runInContext(input.script,context);
const send=(data,source=parent,origin='https://netcap.test')=>listeners.message({data,source,origin});
const changes=[],chart={setOption(o){changes.push(o)}};
const base={title:{text:'Top HTTP Hosts'},legend:{selected:{Requests:false}},xAxis:{type:'category',data:['Requests','<img src=x>']},yAxis:{name:'Requests'},dataZoom:[{start:0,end:100}],visualMap:{min:0,max:99,selected:{a:false}},toolbox:{feature:{saveAsImage:{},restore:{},dataZoom:{},dataView:{},magicType:{},brush:{}}},series:[{type:'bar',name:'Requests',data:[{name:'Requests',id:'canonical-id',value:1234}]}]};
const original=JSON.stringify(base);window.netcapSetChart(chart,base);
assert.equal(base.series[0].data[0].name,'Requests');assert.equal(JSON.stringify(base),original);
const first=changes[0];assert.equal(first.backgroundColor,'#050508');assert.equal(first.series[0].data[0].id,'canonical-id');
const invalid=[null,[],{type:'other',theme:'light',locale:'de'},{type:'netcap:presentation',theme:'system',locale:'de'},{type:'netcap:presentation',theme:'light',locale:'de-DE'},{type:'netcap:presentation',theme:'light',locale:'de',url:'https://evil.test'},{type:'netcap:presentation',theme:'light',locale:'xx'}];
const before=changes.length;for(const d of invalid)send(d);send({type:'netcap:presentation',theme:'light',locale:'de'},{},'https://netcap.test');send({type:'netcap:presentation',theme:'light',locale:'de'},parent,'https://evil.test');assert.equal(changes.length,before);
send({type:'netcap:presentation',theme:'light',locale:'de'});
const patch=changes[before];assert.equal(patch.backgroundColor,'#ffffff');assert.equal(patch.title[0].text,'Häufigste HTTP-Hosts');assert.equal(patch.yAxis[0].name,'Anfragen');assert.equal(patch.legend[0].formatter('Requests'),'Anfragen');assert.equal(patch.visualMap[0].min,undefined);assert.equal(patch.visualMap[0].max,undefined);assert.equal(patch.visualMap[0].selected,undefined);
assert.equal(patch.legend[0].selected,undefined);assert.equal(patch.dataZoom[0].start,undefined);assert.equal(patch.dataZoom[0].end,undefined);assert.equal(patch.series[0].data,undefined);assert.equal(patch.series[0].name,undefined);assert.equal(patch.series[0].id,undefined);
assert.equal(JSON.stringify(base),original);assert.equal(patch.toolbox[0].feature.saveAsImage.title,'Als Bild speichern');assert.equal(patch.toolbox[0].feature.dataView.lang[1],'Schließen');assert.equal(patch.tooltip.formatter({seriesIndex:0,seriesName:'Requests',name:'<img src=x>',value:1234}), '&lt;img src=x&gt; · Anfragen: 1.234');
assert.match(coverage.textContent,/Aufbewahrte/);assert.ok(changes.some(p=>p.graphic&&p.graphic[0].id==='netcap-coverage'&&/Aufbewahrte/.test(p.graphic[0].style.text)));
const pieChanges=[],pie={setOption(o){pieChanges.push(o)}},literal={name:'Requests',value:2},owned={name:'Other',value:3,label:{formatter:window.netcapOwnedLabel('Other')}};
window.netcapSetChart(pie,{legend:{},series:[{type:'pie',name:'Requests',data:[literal,owned]}]});const po=pieChanges[0];assert.equal(po.legend[0].formatter('Requests'),'Requests');assert.equal(po.legend[0].formatter('Other'),'Sonstige');assert.equal(po.series[0].data[0].name,'Requests');
for(const locale of ['en','de','nl','fr','es','zh-Hans']){send({type:'netcap:presentation',theme:'dark',locale});assert.equal(root.lang,locale);}
const collision=[],collisionChart={setOption(o){collision.push(o)}};window.netcapSetChart(collisionChart,{legend:{},series:[{type:'pie',name:'Protocols',data:[{name:'Other',value:1},owned]}]});assert.equal(collision[0].legend[0].formatter('Other'),'Other');
send({type:'netcap:presentation',theme:'light',locale:'de'});const keyLabels=window.netcapAxisLabels({'Requests (2048 bits)':{text:'{algorithm} ({bits} bits)',params:{algorithm:'Requests',bits:2048}}});assert.equal(keyLabels('Requests (2048 bits)'),'Requests (2.048 Bit)');
window.netcapChartConfig.field={auditType:'HTTP',field:'Requests'};
const generic=[],gc={setOption(o){generic.push(o)}};send({type:'netcap:presentation',theme:'light',locale:'de'});window.netcapSetChart(gc,{title:{text:'HTTP - Requests Distribution'},legend:{},series:[{type:'bar',name:'Requests',data:[7]}]});assert.equal(generic[0].title[0].text,'HTTP - Requests Verteilung');assert.equal(generic[0].legend[0].formatter('Requests'),'Requests');
for(const html of input.documents){
 const dl={},elements=new Map(),calls=[],w={parent:{},addEventListener(n,f){dl[n]=f}},d={referrer:'https://netcap.test/app',documentElement:{dataset:{},style:{setProperty(){}}},querySelector(){return null},querySelectorAll(){return []},getElementById(id){if(!elements.has(id))elements.set(id,{style:{}});return elements.get(id)}};
 let initialized=0;const echarts={init(){initialized++;return {setOption(o){calls.push(o)}}}};w.echarts=echarts;
 const c={window:w,document:d,echarts,URL,Intl,TextDecoder,atob};vm.createContext(c);
 for(const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)){if(match[1].trim())vm.runInContext(match[1],c);}
 assert.equal(initialized,1);assert.equal(calls[0].backgroundColor,'#ffffff');assert.ok(calls.some(p=>p.graphic&&p.graphic[0].id==='netcap-coverage'));
 dl.message({data:{type:'netcap:presentation',theme:'dark',locale:'nl'},source:w.parent,origin:'https://netcap.test'});assert.equal(initialized,1);assert.equal(d.documentElement.lang,'nl');
}
`
