package webui

import (
	"bytes"
	"encoding/base64"
	"html"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-echarts/go-echarts/v2/opts"
	echartstypes "github.com/go-echarts/go-echarts/v2/types"
)

type chartPalette struct {
	Background string   `json:"background"`
	Surface    string   `json:"surface"`
	Text       string   `json:"text"`
	Muted      string   `json:"muted"`
	Axis       string   `json:"axis"`
	Grid       string   `json:"grid"`
	Area       string   `json:"area"`
	Emphasis   string   `json:"emphasis"`
	Colors     []string `json:"colors"`
	Ramp       []string `json:"ramp"`
}

var chartPalettes = map[string]chartPalette{
	"dark":  {Background: "#050508", Surface: "#151523", Text: "#e2e8f0", Muted: "#a8b4c8", Axis: "#94a3b8", Grid: "#334155", Area: "#202c45", Emphasis: "#33496b", Colors: []string{"#60a5fa", "#a78bfa", "#38bdf8", "#c4b5fd", "#34d399", "#fbbf24"}, Ramp: []string{"#7c3aed", "#3b82f6", "#67e8f9"}},
	"light": {Background: "#ffffff", Surface: "#f1f5f9", Text: "#172554", Muted: "#475569", Axis: "#64748b", Grid: "#cbd5e1", Area: "#e2e8f0", Emphasis: "#bfdbfe", Colors: []string{"#2563eb", "#7c3aed", "#0369a1", "#6d28d9", "#047857", "#a16207"}, Ramp: []string{"#ddd6fe", "#2563eb", "#075985"}},
}

type chartFieldPresentation struct {
	AuditType    string            `json:"auditType"`
	Field        string            `json:"field"`
	SeriesLabels map[string]string `json:"seriesLabels,omitempty"`
	Groups       bool              `json:"groups,omitempty"`
}

type chartPresentation struct {
	Presentation
	Field     *chartFieldPresentation `json:"field,omitempty"`
	Error     string                  `json:"error,omitempty"`
	Coverage  map[string]string       `json:"coverage"`
	Schematic bool                    `json:"-"`
}

var chartSetOption = regexp.MustCompile(`(goecharts_[A-Za-z0-9_]+)\.setOption\((option_[A-Za-z0-9_]+)\);`)

// presentChartHTML runs after option escaping and before CSP nonce stamping.
func presentChartHTML(document []byte, p chartPresentation) []byte {
	p.Presentation = p.normalized()
	if p.Coverage == nil && p.Error == "" {
		p.Coverage = chartCoverageTexts(nil, p.Schematic)
	}
	config := struct {
		chartPresentation
		Locales  [6]string               `json:"locales"`
		Catalog  map[string][6]string    `json:"catalog"`
		Palettes map[string]chartPalette `json:"palettes"`
	}{p, presentationLocales, chartPresentationCatalog, chartPalettes}
	palette := chartPalettes[p.Theme]
	document = bytes.Replace(document, []byte("<title>Awesome go-echarts</title>"), []byte("<title>Netcap</title>"), 1)
	css := `<style id="netcap-presentation">:root{--nc-bg:` + palette.Background + `;--nc-text:` + palette.Text + `;--nc-muted:` + palette.Muted + `;color-scheme:` + p.Theme + `}html,body,#main,.item,.container,div[_echarts_instance_],body>div{background:var(--nc-bg)!important;color:var(--nc-text)}#rotationToggle{background:#2563eb;color:#fff}#rotationToggle:focus-visible{outline:3px solid var(--nc-text);outline-offset:2px}[data-netcap-coverage]{color:var(--nc-muted)!important}</style>`
	script := `<script>window.netcapChartConfig=` + presentationJSON(config) + `;` + chartPresentationJS + `</script>`
	// Only the library's initialization/call sites change. Capture-derived option
	// literals, series/data names, IDs, links and values are left byte-identical.
	document = bytes.ReplaceAll(document, []byte("echarts.init(document.getElementById("), []byte("window.netcapInitChart(document.getElementById("))
	document = chartSetOption.ReplaceAll(document, []byte(`window.netcapSetChart($1,$2);`))
	if p.Coverage != nil {
		annotation := `<aside role="note" data-netcap-coverage="v1" style="position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:pre-wrap">` + html.EscapeString(p.Coverage[p.Locale]) + `</aside>`
		document = bytes.Replace(document, []byte("</body>"), []byte(annotation+"</body>"), 1)
	}
	if bytes.Contains(document, []byte("<head>")) {
		document = bytes.Replace(document, []byte("<head>"), []byte("<head>"+script), 1)
		if bytes.Contains(document, []byte("</head>")) {
			document = bytes.Replace(document, []byte("</head>"), []byte(css+"</head>"), 1)
		} else {
			document = bytes.Replace(document, []byte("<head>"), []byte("<head>"+css), 1)
		}
	} else {
		document = append([]byte(css+script), document...)
	}
	return document
}

// Only explicitly synthesized categories receive this formatter. Names remain
// canonical English, including in click events and legend selection maps.
func chartOwnedLabel(english any) *opts.Label {
	return &opts.Label{Formatter: opts.FuncOpts(`window.netcapOwnedLabel(` + chartJSValue(english) + `)`)}
}

// go-echarts removes FuncOpts markers without unquoting the embedded JS string.
// An ASCII-only operand avoids its double-quote/backslash corruption, including
// for captured Unicode keys in an explicitly owned axis-label map.
func chartJSValue(value any) string {
	return `window.netcapDecodeUI('` + base64.StdEncoding.EncodeToString([]byte(presentationJSON(value))) + `')`
}

// A literal capture value wins a collision with a synthesized fallback label.
type chartLabelSet struct {
	fallbacks map[string]any
	literals  map[string]bool
}

type chartTextTemplate struct {
	Text   string         `json:"text"`
	Params map[string]any `json:"params,omitempty"`
}

func newChartLabelSet() *chartLabelSet {
	return &chartLabelSet{fallbacks: map[string]any{}, literals: map[string]bool{}}
}

func (labels *chartLabelSet) name(value, fallback string) string {
	if value != "" {
		labels.literals[value] = true
		return value
	}
	labels.fallbacks[fallback] = fallback
	return fallback
}

func (labels *chartLabelSet) label(name string) *opts.Label {
	if text, ok := labels.fallbacks[name]; ok && !labels.literals[name] {
		return chartOwnedLabel(text)
	}
	return nil
}

func (labels *chartLabelSet) axisFormatter() echartstypes.FuncStr {
	names := map[string]any{}
	for name, english := range labels.fallbacks {
		if !labels.literals[name] {
			names[name] = english
		}
	}
	return opts.FuncOpts(`window.netcapAxisLabels(` + chartJSValue(names) + `)`)
}

const chartPresentationJS = `(function(){
'use strict';
var cfg=window.netcapChartConfig, current={theme:cfg.theme,locale:cfg.locale}, charts=[], coverage=cfg.coverage;
var own=Object.prototype.hasOwnProperty;
function list(v){return Array.isArray(v)?v:(v?[v]:[]);}
function tr(s){if(typeof s!=='string')return s;var row=own.call(cfg.catalog,s)?cfg.catalog[s]:null;if(row)return row[cfg.locales.indexOf(current.locale)];var group=/^Group ([1-5])$/.exec(s);return group?tr('Group')+' '+group[1]:s;}
function palette(){return cfg.palettes[current.theme];}
function number(v){return typeof v==='number'?new Intl.NumberFormat(current.locale,{maximumFractionDigits:6}).format(v):String(v==null?'':v);}
function uiText(spec){if(typeof spec==='string')return tr(spec);if(!spec||typeof spec.text!=='string')return String(spec==null?'':spec);return tr(spec.text).replace(/\{([A-Za-z]+)\}/g,function(token,key){var v=(spec.params||{})[key];return v==null?token:(typeof v==='number'?number(v):typeof v==='object'?uiText(v):String(v));});}
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function merge(a,b){var o=Object.assign({},a||{});Object.keys(b).forEach(function(k){var v=b[k];if(Array.isArray(v))o[k]=v.map(function(x,i){return x&&typeof x==='object'&&!Array.isArray(x)?merge(list(o[k])[i],x):x;});else if(v&&typeof v==='object')o[k]=merge(o[k],v);else o[k]=v;});return o;}
function fieldTitle(s){if(!cfg.field)return tr(s);var prefix=cfg.field.auditType+' - ',middle=cfg.field.field;var names=['Distribution','Funnel','Radar','Word Cloud','Distribution Funnel','Network Graph'];if(s===cfg.field.auditType+' - Flow Diagram')return cfg.field.auditType+' - '+tr('Flow Diagram');for(var i=0;i<names.length;i++){if(s===prefix+middle+' '+names[i])return prefix+middle+' '+tr(names[i]);}return s;}
function itemNames(series){var names=Object.create(null),literals=Object.create(null);function visit(items){list(items).forEach(function(d){if(!d||typeof d!=='object')return;var f=d.label&&d.label.formatter;if(typeof f==='function'&&f.netcapUI!==undefined)names[d.name]=f.netcapUI;else if(d.name)literals[d.name]=true;visit(d.children);});}visit(series.data);Object.keys(literals).forEach(function(n){delete names[n];});return names;}
window.netcapOwnedLabel=function(text){var f=function(p){var value=Array.isArray(p.value)?p.value.map(number).join(', '):number(p.value);return uiText(text)+': '+value+(p.percent==null?'':' ('+number(p.percent)+'%)');};f.netcapUI=text;return f;};
window.netcapDecodeUI=function(encoded){return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(encoded),function(c){return c.charCodeAt(0);})))};
window.netcapAxisLabels=function(names){var f=function(value){return own.call(names,value)?uiText(names[value]):value;};f.netcapUI=names;return f;};
window.netcapLegendLabel=function(name){return tr(name);};window.netcapLegendLabel.netcapOwnedLegend=true;
window.netcapLayerLabel=function(p){return p.treePathInfo&&p.treePathInfo.length===2?tr(p.name):p.name;};
function seriesTitle(s){if(!cfg.field){var aliases={protocols:'Protocols',hosts:'Hosts',observed:'Observed'};return tr(own.call(aliases,s)?aliases[s]:s);}return cfg.field.seriesLabels&&own.call(cfg.field.seriesLabels,s)?tr(cfg.field.seriesLabels[s]):s;}
function tooltip(base,allNames){return function(params){return list(params).map(function(p){var s=list(base.series)[p.seriesIndex]||{},names=allNames[p.seriesIndex]||{},label=p.data&&p.data.label&&p.data.label.formatter,name=label&&label.netcapUI?uiText(label.netcapUI):(own.call(names,p.name)?uiText(names[p.name]):p.name);if(s.label&&s.label.formatter===window.netcapLayerLabel&&p.treePathInfo&&p.treePathInfo.length===2)name=tr(p.name);var value=Array.isArray(p.value)?p.value.map(number).join(', '):number(p.value);var f=(s.tooltip&&s.tooltip.formatter)||(base.tooltip&&list(base.tooltip)[0]&&list(base.tooltip)[0].formatter);if(typeof f==='string'){f=tr(f);return f.replace(/\{([abcd])\}/g,function(_,key){return esc(key==='a'?seriesTitle(p.seriesName):key==='b'?name:key==='d'?number(p.percent):value);});}return esc(name)+(p.seriesName?' · '+esc(seriesTitle(p.seriesName)):'')+': '+esc(value)+(p.percent==null?'':' ('+esc(number(p.percent))+'%)');}).join('<br>');};}
function axis(a){var p=palette(),label={color:p.muted};if(a.type!=='category'&&a.type!=='time'&&!a.data)label.formatter=function(v){return number(v);};return {name:tr(a.name),nameTextStyle:{color:p.text},axisLabel:label,axisLine:{lineStyle:{color:p.axis}},axisTick:{lineStyle:{color:p.axis}},splitLine:{lineStyle:{color:p.grid}},splitArea:{areaStyle:{color:[p.background,p.surface]}},axisPointer:{label:{color:p.text,backgroundColor:p.surface}}};}
function patch(base){var p=palette(),allNames=list(base.series).map(itemNames),legendNames=Object.create(null),seriesNames=Object.create(null);allNames.forEach(function(n){Object.keys(n).forEach(function(k){legendNames[k]=n[k];});});list(base.series).forEach(function(s){if(['pie','funnel','graph','sankey','sunburst','treemap','wordCloud'].indexOf(s.type)<0)seriesNames[s.name]=true;if(cfg.field&&cfg.field.groups)list(s.categories).forEach(function(d){legendNames[d.name]=d.name;});});list(base.xAxis).forEach(function(a){var names=a.axisLabel&&a.axisLabel.formatter&&a.axisLabel.formatter.netcapUI;if(names&&typeof names==='object')allNames.forEach(function(n){Object.keys(names).forEach(function(k){n[k]=names[k];});});});
var o={backgroundColor:p.background,color:p.colors,textStyle:{color:p.text},title:list(base.title).map(function(t){return {text:fieldTitle(t.text),subtext:fieldTitle(t.subtext),textStyle:{color:p.text},subtextStyle:{color:p.muted}};}),tooltip:{backgroundColor:p.surface,borderColor:p.axis,textStyle:{color:p.text},formatter:tooltip(base,allNames)},legend:list(base.legend).map(function(l){return {textStyle:{color:p.text},pageTextStyle:{color:p.muted},pageIconColor:p.text,pageIconInactiveColor:p.axis,inactiveColor:p.muted,formatter:l.formatter&&l.formatter.netcapOwnedLegend?l.formatter:function(n){return own.call(legendNames,n)?uiText(legendNames[n]):(own.call(seriesNames,n)?seriesTitle(n):n);}};})};
['xAxis','yAxis','xAxis3D','yAxis3D','zAxis3D','radiusAxis','angleAxis','parallelAxis','singleAxis'].forEach(function(k){if(base[k])o[k]=list(base[k]).map(axis);});
if(base.yAxis3D&&list(base.legend).some(function(l){return l.formatter&&l.formatter.netcapOwnedLegend;}))list(base.yAxis3D).forEach(function(a,i){if(a.type==='category'&&a.name==='Layer')o.yAxis3D[i].axisLabel.formatter=window.netcapLegendLabel;});
if(base.radar)o.radar=list(base.radar).map(function(){return {axisName:{color:p.text},axisLine:{lineStyle:{color:p.axis}},splitLine:{lineStyle:{color:p.grid}},splitArea:{areaStyle:{color:[p.background,p.surface]}}};});
if(base.geo)o.geo=list(base.geo).map(function(){return {itemStyle:{areaColor:p.area,borderColor:p.axis},label:{color:p.text},emphasis:{itemStyle:{areaColor:p.emphasis},label:{color:p.text}}};});
if(base.grid3D)o.grid3D=list(base.grid3D).map(function(){return {environment:p.background,axisLine:{lineStyle:{color:p.axis}},axisLabel:{color:p.text},axisPointer:{lineStyle:{color:p.axis},label:{color:p.text}},splitLine:{lineStyle:{color:p.grid}}};});
if(base.visualMap)o.visualMap=list(base.visualMap).map(function(v){return {textStyle:{color:p.text},text:list(v.text).map(tr),inRange:{color:p.ramp},outOfRange:{color:[p.area]}};});
if(base.dataZoom)o.dataZoom=list(base.dataZoom).map(function(){return {textStyle:{color:p.muted},borderColor:p.axis,backgroundColor:p.surface,fillerColor:current.theme==='dark'?'rgba(96,165,250,0.25)':'rgba(37,99,235,0.18)',handleStyle:{color:p.axis,borderColor:p.text},moveHandleStyle:{color:p.axis},dataBackground:{lineStyle:{color:p.axis},areaStyle:{color:p.area}},selectedDataBackground:{lineStyle:{color:p.colors[0]},areaStyle:{color:p.area}}};});
o.toolbox=list(base.toolbox).map(function(t){var features={};Object.keys(t.feature||{}).forEach(function(k){var titles={saveAsImage:tr('Save as Image'),restore:tr('Restore'),dataView:tr('Data View'),dataZoom:{zoom:tr('Zoom'),back:tr('Reset')},magicType:{line:tr('Line'),bar:tr('Bar'),stack:tr('Stack'),tiled:tr('Tiled')},brush:{rect:tr('Rectangle selection'),polygon:tr('Polygon selection'),lineX:tr('Horizontal selection'),lineY:tr('Vertical selection'),keep:tr('Keep selection'),clear:tr('Clear selection')}};features[k]={title:titles[k]||tr(t.feature[k].title)};if(k==='saveAsImage')features[k].backgroundColor=p.background;if(k==='dataView')Object.assign(features[k],{lang:[tr('Data View'),tr('Close'),tr('Refresh')],backgroundColor:p.background,textareaColor:p.surface,textareaBorderColor:p.axis,textColor:p.text,buttonColor:p.colors[0],buttonTextColor:'#fff'});});return {iconStyle:{borderColor:p.muted},emphasis:{iconStyle:{borderColor:p.text}},feature:features};});
o.series=list(base.series).map(function(s){var label={color:p.text,textBorderWidth:0};if(['pie','treemap','sunburst','funnel','bar3D'].indexOf(s.type)>=0)Object.assign(label,{backgroundColor:p.background,padding:2,borderRadius:2});var result={label:label,upperLabel:{color:p.text,backgroundColor:p.background},emphasis:{label:{color:p.text,textBorderWidth:0}},blur:{label:{color:p.muted}},labelLine:{lineStyle:{color:p.axis}}};if(s.type==='wordCloud'){var color=function(){var colors=palette().colors;return colors[Math.floor(Math.random()*colors.length)];};result.textStyle={color:color,normal:{color:color}};}if(s.type==='map')result.itemStyle={areaColor:p.area,borderColor:p.axis};if(s.type==='graph'||s.type==='sankey')result.lineStyle={color:p.axis};return result;});
if(list(base.series).every(function(s){return !list(s.data).length||list(s.data).every(function(d){return d&&d.value===0&&d.label&&d.label.formatter&&d.label.formatter.netcapUI==='No devices';});}))o.graphic=[{id:'netcap-no-data',type:'text',left:'center',top:'middle',silent:true,style:{text:tr('No chart data'),fill:p.muted,fontSize:14}}];
return o;}
function updateCoverage(){if(!coverage)return;var message=coverage[current.locale],p=palette();document.querySelectorAll('[data-netcap-coverage]').forEach(function(el){el.textContent=message;});charts.forEach(function(entry){entry.chart.setOption({graphic:[{id:'netcap-coverage',type:'text',left:8,bottom:2,silent:true,style:{text:message.replace(/ · /g,'\n'),fill:p.muted,backgroundColor:p.background,width:Math.max(80,(window.innerWidth||600)-24),overflow:'break',padding:2,fontSize:9,lineHeight:11}}]});});}
window.netcapSetCoverage=function(messages){coverage=messages;updateCoverage();};
function chrome(){var p=palette(),root=document.documentElement;root.lang=current.locale;root.dataset.netcapTheme=current.theme;root.style.colorScheme=current.theme;root.style.setProperty('--nc-bg',p.background);root.style.setProperty('--nc-text',p.text);root.style.setProperty('--nc-muted',p.muted);if(charts.length)document.title=fieldTitle((list(charts[0].base.title)[0]||{}).text)||'Netcap';var button=document.getElementById('rotationToggle');if(button)button.textContent=tr(window.rotationEnabled===false?'▶ Resume Rotation':'⏸ Pause Rotation');var error=document.querySelector('[data-netcap-error]');if(error)error.textContent=tr(cfg.error||'Chart unavailable');var diagnostic=document.querySelector('[data-netcap-diagnostic]');if(diagnostic)diagnostic.textContent=tr('Diagnostic details');}
window.netcapChartText=tr;
window.netcapChartPalette=palette;
window.netcapInitChart=function(el,theme,options){return window.echarts.init(el,null,options);};
window.netcapSetChart=function(chart,base){charts.push({chart:chart,base:base});chart.setOption(merge(base,patch(base)));updateCoverage();};
var expectedOrigin='';try{if(document.referrer)expectedOrigin=new URL(document.referrer).origin;}catch(_){}
window.addEventListener('message',function(event){if(window.parent===window||event.source!==window.parent)return;if(expectedOrigin&&expectedOrigin!=='null'&&event.origin!==expectedOrigin)return;var d=event.data;if(!d||typeof d!=='object'||Array.isArray(d)||Object.keys(d).sort().join(',')!=='locale,theme,type'||d.type!=='netcap:presentation'||(d.theme!=='dark'&&d.theme!=='light')||cfg.locales.indexOf(d.locale)<0)return;if(current.theme===d.theme&&current.locale===d.locale)return;current={theme:d.theme,locale:d.locale};chrome();charts.forEach(function(entry){entry.chart.setOption(patch(entry.base));});updateCoverage();});
chrome();updateCoverage();window.addEventListener('load',function(){chrome();updateCoverage();},{once:true});
window.addEventListener('resize',updateCoverage);
})();`

func chartPresentationFromRequest(r *http.Request) chartPresentation {
	path := r.URL.Path
	return chartPresentation{Presentation: PresentationFromRequest(r), Schematic: strings.Contains(path, "sankey") || strings.Contains(path, "protocol-hierarchy") || strings.Contains(path, "/visualize/graph")}
}
