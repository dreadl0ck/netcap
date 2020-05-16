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

package encoder

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/evilsocket/islazy/tui"

	deadlock "github.com/sasha-s/go-deadlock"


	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/ua-parser/uap-go/uaparser"
)

type Software struct {
	*types.Software
	deadlock.Mutex
}

// AtomicDeviceProfileMap contains all connections and provides synchronized access
type AtomicSoftwareMap struct {
	// mapped product + version to software
	Items map[string]*Software
	deadlock.Mutex
}

var (
	userAgentCaching = make(map[string]*userAgent)
	regExpServerName = regexp.MustCompile(`(.*?)(?:(?:/)(.*?))?(?:\s*?)(?:(?:\()(.*?)(?:\)))?$`)
	regexpXPoweredBy = regexp.MustCompile(`(.*?)(?:(?:/)(.*?))?$`)
	ja3Cache         = make(map[string]string)
	jaCacheMutex     deadlock.Mutex
	reGenericVersion = regexp.MustCompile(`(?m)(?:^)(.*?)([0-9]+)\.([0-9]+)\.([0-9]+)(.*?)(?:$)`)
	hasshMap         = make(map[string][]SSHSoftware)
	cmsDB            = make(map[string]interface{})
)

// Size returns the number of elements in the Items map
func (a *AtomicSoftwareMap) Size() int {
	a.Lock()
	defer a.Unlock()
	return len(a.Items)
}

var (
	// SoftwareStore hold all connections
	SoftwareStore = &AtomicSoftwareMap{
		Items: make(map[string]*Software),
	}

	parser, errInitUAParser = uaparser.New("/usr/local/etc/netcap/dbs/regexes.yaml")
	pMu                     deadlock.Mutex

	ja3db   Ja3CombinationsDB
	hasshDB []SSHHash
)

//var CSMMeta []string = []string{"elqCurESit", "MRHSHin", "foswiki.WIKINAM", "Kajab", "PHPSESSI", "NREU", "_ACPuzzl", "dps_site_i", "pyrocm", "google_tag_manage", "rlAppVersio", "i_like_gogit", "SyntaxHighlighte", "Crite", "_zendesk_shared_sessio", "Phase", "vgln", "cs_secure_sessio", "googleta", "usabilla_liv", "_goStatsRu", "e107_t", "Immutabl", "babli", "Captchm", "OWA.config.baseUr", "rainloopI18", "_gauge", "Larave", "ct_nOp", "ado.maste", "powered-b", "csrf-para", "ATInterne", "advst_is_above_the_fol", "Rx.Symbo", "OJSSI", "$jit.versio", "analytic", "gsapVersion", "catberry.versio", "MODX_MEDIA_PAT", "IsOwaPremiumBrowse", "Shapecs", "ngMateria", "Min", "jQuery.mobile.versio", "firebase.SDK_VERSIO", "EC_ROOT_DOMAI", "_COMSCOR", "nv.versio", "tc_var", "Ecwi", "dle_roo", "mejs.versio", "foswiki.SERVERTIM", "og", "robin_storage_setting", "F5_S", "bit", "Infern", "ct_nSuUr", "AnalysysAgen", "ko.versio", "wt_t", "vaadi", "CKEDITO", "__SENTRY_", "hubspo", "Countl", "TypechoCommen", "Ex", "Stackl", "Fingerprint", "PUBLICCMS_USE", "MooTool", "Gravata", "_zendesk_cooki", "_cfEmail", "gbWhLan", "_carbonad", "_hs", "cp_C4w1ldN2d9PmVrk", "sc_securit", "nette-browse", "Mag", "Ha.VERSIO", "ShellInABo", "Raven.confi", "flyspray_projec", "Kinetic.versio", "ravenOptions.whitelistUrl", "ahoy_trac", "Braintre", "Cufo", "fbit", "phpb", "oxTopMen", "_bsa", "versio", "MyB", "MOD", "protovi", "Elm.Main.ini", "AlgoliaSearc", "basket.isValidIte", "priceDisplayPrecisio", "gaplugins.E", "UC_ITEM_INFO_SERVIC", "Braintree.versio", "osCsi", "ng.prob", "REVEL_SESSIO", "OCSESSI", "SFDCCm", "EPiTrac", "MAKACSESSIO", "_mf", "eomportal-i", "YStor", "__gvizguard_", "window.LOJA_I", "squirrelmail_loginpage_onloa", "epage", "EcwidCar", "Ushahid", "Vue.versio", "LF.CommentCoun", "oxInputValidato", "freeProductTranslatio", "reinvigorat", "TEALIUMENABLE", "jcomment", "clickHeatServe", "Hamme", "RakutenApplicatio", "DOCUMENTATION_OPTION", "tinyMCE.majorVersio", "rcmai", "JetshopDat", "cakeph", "Rx.CompositeDisposabl", "CRLT.CONFIG.ASMJS_NAM", "Dynamicwe", "__vw", "__avng8", "SonarReques", "WHMC", "_g", "k_visi", "Comandi", "swa", "AmChart", "catberr", "MaterialIconToggl", "SC_ANALYTICS_GLOBAL_COOKI", "recaptch", "jQuery.fn.tooltip.Constructor.VERSIO", "kmGetSessio", "piAI", "_ga", "gemius_hi", "Squarespac", "Snap.versio", "jQuery.pja", "ahoy_visi", "Decimal.ROUND_HALF_FLOO", "Backbone.VERSIO", "jenkinsCIGloba", "YII_CSRF_TOKE", "Copyrigh", "momen", "VW", "Jobbe", "fronten", "_gitlab_sessio", "efCor", "discuzVersio", "bootstrap.Alert.VERSIO", "Wicke", "ci_sessio", "Sfj", "elementorFrontend.getElement", "Gerri", "wsc_rendermod", "__derak_use", "wik", "oxModalPopu", "Inferno.versio", "__inspl", "disqus_shortnam", "gl.dashboardOption", "CCM_IMAGE_PAT", "foswik", "keyword", "bf_sessio", "requirejs.versio", "titl", "Sentr", "signalDat", "sublimevide", "Embe", "Instabo", "exp_last_activit", "padimpex", "_usr", "__gwtlistene", "gr_user_i", "PREBID_TIMEOU", "gemius_ini", "hj.apiUrlBas", "mivaJS.Scree", "_klarnaCheckou", "app.cache.discussionLis", "mivaJS.Product_I", "VtexWorkspac", "Ray", "_bubble_page_load_dat", "blessing.versio", "Backdro", "GSF", "hljs.listLanguage", "marke", "elqSiteI", "bugsnagClien", "Matom", "kampyl", "bigwareCsi", "shope", "SobiProUr", "___dart__$dart_dartObject_ZxYxX_0", "_satellit", "Shopcad", "_robin_getRobinJ", "__gwt_getMetaPropert", "ScrollReveal().versio", "parcelRequir", "Bugsna", "s_accoun", "HelloBa", "_gphw_mod", "bounce", "eny", "PDFJ", "Ionic.versio", "adroll_adv_i", "_sf_endp", "lm_onlin", "_sf_async_confi", "Immutable.versio", "smf", "xliteConfi", "shptUr", "prettyPrin", "FOSWIKISTRIKEON", "ipb_va", "Modernizr._versio", "Hoga", "DISQU", "__gwt", "Marionett", "WEBXPA", "gbWhMs", "CMSPreferredCultur", "wink.versio", "Pris", "MemberStac", "MoodleSessio", "go.GraphObjec", "yandex_metrik", "laravel_sessio", "search.indexNam", "Boke", "RISK", "SWFObjec", "LiveStor", "FyreLoade", "___dart_dispatch_record_ZxYxX_0", "L.PosAnimatio", "DC.identifie", "_pa", "Sweetalert", "_hybri", "botble_sessio", "adxinserthtm", "AjaxShoppingCar", "woocommerce_param", "_statcounte", "xi", "ef.versio", "DISCUZCOD", "SmartAdServe", "s_objectI", "soundManager.versio", "Umbrac", "Harava", "particlesJ", "xcart_web_di", "EPiServe", "gaGloba", "Webz", "ushahid", "Foundation.versio", "__gwt_activeModule", "confluence-request-tim", "FESESSIONI", "CloudFlar", "IPBoar", "LSHelper", "Fingerprin", "UserVoic", "AU", "mixpane", "Fingerprint2.VERSIO", "criteo_pubta", "cpsessio", "ICMSSessio", "AWSAL", "MivaVM_AP", "react.versio", "application-nam", "sensorsdata2015jssdkcros", "SFDCSessionVar", "galleryAuthToke", "Client.Anonymou", "Interco", "kendo.versio", "Posterou", "BUGZILL", "adrive", "jQuery.fn.select", "sensorsdata2015sessio", "Webflo", "web_autho", "mivaJS.Product_Cod", "BaconPlaye", "wp_usernam", "dayj", "d3.versio", "jiraf", "taigaConfi", "Redoc.versio", "elqLoa", "React.versio", "wgSessio", "optimizel", "ASP.NET_SessionI", "avng8", "Jooml", "pdfjs-dist/build/pdf.versio", "com.salesforc", "TrackJ", "JSChar", "Autho", "Shiny.addCustomMessageHandle", "LiveAgen", "exp_csrf_toke", "videojs.VERSIO", "_bs", "ajs-version-numbe", "HotleadControlle", "Mustache.versio", "owa_cmd", "CryptoLoo", "webtrekkUnloadObject", "pinoo", "L.DistanceGri", "pma_absolute_ur", "_bsap_serving_callbac", "epomCustomParam", "Ember.VERSIO", "xt_clic", "KAMPYLE_COMMO", "El", "eomportal-instancei", "derakCloud.ini", "tiddlywiki-versio", "_help_center_sessio", "PLAY_SESSIO", "ClarityIcon", "spincms_sessio", "style_cookie_setting", "MM_showHideLayer", "zbxCallPostScript", "Chart.defaults.doughnu", "Kineti", "pdfjsLib.versio", "YUI.versio", "Plotly.versio", "LHread", "X-Imperia-Live-Inf", "MauticTrackingObjec", "gemius_pendin", "pjax-timeou", "ahoy_visito", "AWSEL", "jQuery.fn.jquer", "$ji", "rdoc_rel_prefi", "chart.ctx.bezierCurveT", "YAHOO.VERSIO", "szmvar", "webtrekkHeatmapObject", "DotNetNukeAnonymou", "jseMin", "k_trac", "Bugzilla_login_request_cooki", "google_ad", "eomportal-uui", "cnzz_protoco", "Transifex.live.lib_versio", "jQuery.ui.versio", "wt_ttv", "_gauges", "__mobxGloba", "Makesho", "mm_current_user_i", "TweenMa", "IAI_Aja", "addthi", "ProgI", "FTB_AddEven", "MM_showMen", "rainloo", "tiddle", "_adcopy-puzzle-image-imag", "titanEnable", "ct_siteunde", "head.browser.nam", "SIM.mediu", "__APOLLO_CLIENT_", "MOODLEID", "phsi", "quantserv", "__derak_aut", "october_sessio", "laterpay", "pligg", "mivaJ", "GoogleAnalyticsObjec", "K2RatingUR", "pp_gemius_hi", "_monoTracke", "VtexFingerPrin", "__SAPPER_", "bigWAdminI", "pp_title", "DedeContaine", "pwidget_confi", "yandex_ad_forma", "google-play-ap", "_W.configDomai", "asciinem", "pw_adloade", "mathj", "WebTrend", "Bokeh.versio", "WTOptimiz", "MakeshopLogUniqueI", "OSTSESSI", "_.differenceB", "koken_referre", "adroll_pix_i", "Quil", "VuVeoxaConten", "adosResult", "Munchki", "doj", "kend", "UserEngag", "MM_preloadImage", "gbWhUti", "Ricksha", "ado", "xtsit", "discuz_ui", "SuUr", "Domai", "pp_image", "sensorsdata_app_js_bridge_call_j", "a2apage_ini", "OneStat_Pagevie", "LastMRH_Sessio", "ArtifactoryUpdate", "__APOLLO_CLIENT__.versio", "_kjb_sessio", "EPrint", "ekmpowersho", "criteo_", "piTracke", "Highchart", "mivaJS.Pag", "angula", "ASPSESSIO", "roundcub", "ngTestabilityRegistrie", "XRegExp.versio", "ipbWWLsession_i", "GitLa", "CMSSESSI", "_.VERSIO", "sf_redirec", "MRHSessio", "setMIfram", "GENERATO", "SuLoade", "autho", "Phoeni", "websale_a", "MochiKi", "gx.gxVersio", "cargo_titl", "go.versio", "pjax-replac", "Meteo", "ipsSetting", "MathJax.versio", "Lis", "TWIKISI", "_session_i", "ct_ta", "padeditba", "angular.version.ful", "PAYPA", "bitbucke", "newreli", "apple-itunes-ap", "BWEU", "hea", "clickTaleStartEventSigna", "fligh", "__mobxInstanceCoun", "phpdebugba", "Swiftyp", "eomportal-lastUpdat", "InstantCMS[logdate", "Marionette.VERSIO", "gbWhVe", "DotNetNuk", "Shopif", "Exhibi", "_.restArgument", "_solusquar", "JSESSIONI", "Typekit.config.j", "i_like_gite", "DC.titl", "LinkSmar", "Drupa", "ImpressCM", "DokuWik", "vl_disabl", "vivv", "videoj", "priceDisplayMetho", "ZM_TES", "eomportal-loi", "tita", "hotaru_mobil", "elq_globa", "PrestaSho", "_babelPolyfil", "JTLSHO", "click", "Raycha", "SHARETHI", "vBulleti", "ng.coreToken", "UC_SETTING", "clob", "CoinHiv", "Goog_AdSense", "dojo.version.majo", "bubble_hostname_modifie", "Flickit", "moment.versio", "Backbon", "mm_use", "graffitibo", "piHostnam", "__admin_media_prefix_", "xf_sessio", "wixBiSessio", "SFOSWIKISI", "bubble_environmen", "KM_COOKIE_DOMAI", "cprelogi", "_redmine_sessio", "__googleVisualizationAbstractRendererElementsCount_", "exp_tracke", "Zept", "io.versio", "asciido", "mm_licens", "Shin", "CodeMirror.versio", "CE", "rio", "pp_alreadyInitialize", "designe", "REVEL_FLAS", "Zenfoli", "nv.addGrap", "ARRAffinit", "datadom", "Nett", "ado.slav", "ch_clien", "blesta_si", "oxLoginBo", "SPDesignerProgI", "eZSESSI", "CKEDITOR.versio", "PhpDebugBa", "mermai", "TiPMi", "Highcharts.versio", "_fusio", "PARSEL", "typeahea", "setMRefUR", "Keyword", "disqus_ur", "OpenLayers.VERSION_NUMBE", "generato", "FTB_AP", "Grand.custome", "Nop.custome", "PUNB", "PrefixFre", "xoop", "Powered-B", "CodeMirro", "bbsessionhas", "yandex_partner_i", "Elm.Main.embe", "WebtrekkV", "Handlebar", "Fusion.arcSit", "OB_releaseVe", "cookie_nam", "EC_GLOBAL_DATETIM", "ch_color_site_lin", "COMSCOR", "Colorm", "PDFJS.versio", "Handlebars.VERSIO", "gerrit_u", "Zone.roo", "ArvanClou", "webi", "volusio", "pdfjsDistBuildPdf.versio", "memberstac", "jQuery.migrateWarning", "mm_confi", "ol.CanvasMa", "Swipe", "webtrekkLinktrackObject", "vtex_sessio", "__mobxGlobal", "EC_GLOBAL_INF", "Pagevam", "LithiumVisito", "swell-sessio", "show_switch2gu", "Prototype.Versio", "webtrekkV", "kohanasessio", "fn_compare_string", "iexexchanger_sessio", "_pdfjsCompatibilityChecke", "NS_VE", "xf_csr", "Ext.versio", "s_INS", "bubble_versio", "sa.lib_versio", "s_cod", "UC_IMAGE_SERVICE|ITEM_INFO_SERVIC", "RightJ", "OpenGro", "piCI", "kmPageInf", "L.versio", "piProtoco", "__chang", "Recaptch", "hljs.highlightBloc", "go_msi", "sap.ui.versio", "VideoJ", "TI", "NET", "SonarMeasure", "_spBodyOnLoadCalle", "descriptio", "ipbWWLmodpid", "PIWIK_SESSI", "YW", "AFRAME.versio", "Kamv", "io.Socke", "OutbrainPermaLin", "MRHSequenc", "ActO", "jQ", "Piwi", "aho", "__ins", "Scriptaculous.Versio", "ZENDSERVERSESSI", "TNE", "gbWhProx", "Polymer.versio", "_bsaPR", "SoundManage", "__cfdui", "ci_csrf_toke", "Sentry.SDK_VERSIO", "__utm", "mivaJS.Store_Cod", "XF.GuestUsernam", "webtrek", "snoob", "dnn.apiversio", "LIVESTREET_SECURITY_KE", "F5_HT_shrinke", "copyrigh", "gwt", "pbj", "Nette.versio", "ucCatalo", "VivvoSessionI", "3dvisi", "webtrekkConfi", "Hammer.VERSIO", "Discours", "vl_c", "_ekmpinpoin", "_.templateSettings.imports._.templateSettings.imports._.VERSIO", "reddi", "og", "HotLeadfactor", "awesomplet", "M.cor", "CKEDITOR_BASEPAT", "algoliasearch.versio", "ac_bgclick_UR", "jir", "swell.versio", "ACPuzzl", "sc_projec", "INVENIOSESSIO", "$nux", "THREE.REVISIO", "Y.Moodl", "webpackJson", "F5_fullW", "__gwt_isKnownPropertyValu", "EPJS_menu_templat", "jenkinsRule", "Luigi", "MathJa", "SSsd", "SFDCAp", "RDStatio", "CraftSessionI", "Char", "adcopy-puzzle-image-imag", "phpcm", "Reveal.VERSIO", "adyen.encrypt.versio", "_mb_site_gui", "Stripe.versio", "SystemI", "__google_ad_url", "pp_description", "MochiKit.MochiKit.VERSIO", "__NEXT_DATA_", "$.fancybox.versio", "MooTools.versio", "pjax-pus", "shopte", "Telescop", "Bizwe", "shopf", "Exhibit.versio", "actionheroClien", "bblastvisi", "WebFont", "djang", "Phaser.VERSIO", "zano", "xChar", "ant", "dwAnalytic", "twemoj", "$.fn.gallery_valig", "robin_setting", "Mobif", "OAS_A", "gambi", "Sazit", "esyndica", "style", "pinoox_sessio", "grwng_ui", "sails.si", "oxCookieNot", "__gwt_stylesLoade", "app.forum.freshnes", "jQuery.migrateVersio", "Lifera", "riskifiedBeaconLoa", "ARK_I", "CONCRETE", "LITHIU", "TeaLea", "ado.placemen", "owa_baseUr", "bblastactivit", "bugsna", "uCo", "fyr", "mw.util.toggleTo", "Timeplo", "iam_dat", "AWSALBCOR", "deepMine", "_go_track_sr", "Ext.versions.extjs.versio", "Ionic.confi", "jqueryMigrat", "VarienFor", "MivaVM_Versio", "Raphael.versio", "Meteor.releas", "SFDCPag", "MOIN_SESSIO", "mej", "LS_JSO", "KOH"}

type userAgent struct {
	client  *uaparser.Client
	product string
	vendor  string
	version string
	full    string
}

type Process struct {
	Process string `json:"process"`
	JA3     string `json:"JA3"`
	JA3s    string `json:"JA3S"`
}

type Client struct {
	Os        string    `json:"os"`
	Arch      string    `json:"arch"`
	Processes []Process `json:"processes"`
}

type Server struct {
	Server  string   `json:"server"`
	Clients []Client `json:"clients"`
}

type Ja3CombinationsDB struct {
	Servers []Server `json:"servers"`
}

type SSHSoftware struct {
	Version    string `json:"name"`
	Likelyhood string `json:"likelyhood"`
}

type SSHHash struct {
	Hash      string        `json:"hash"`
	Softwares []SSHSoftware `json:"software"`
}

// type AppInfo struct {
// 	headers map[string]interface{} `json:"headers"`
// 	cookies map[string]interface{} `json:"cookies"`
// }

// type App struct {
// 	name
// }

// process a raw user agent string and returned a structured instance
func parseUserAgent(ua string) *userAgent {
	var (
		client                         = parser.Parse(ua)
		full, product, vendor, version string
	)
	if client.UserAgent != nil {
		vendor = client.UserAgent.Family
		version = client.UserAgent.Major
		if client.UserAgent.Minor != "" {
			version += "." + client.UserAgent.Minor
		}
		if client.UserAgent.Patch != "" {
			version += "." + client.UserAgent.Patch
		}
		full += " " + client.UserAgent.Family
		full += " " + client.UserAgent.Major
		full += " " + client.UserAgent.Minor
		full += " " + client.UserAgent.Patch

		if vendor == "Other" {
			vendor = ""
		}
	}
	if client.Os != nil {
		full += " " + client.Os.Family
		full += " " + client.Os.Major
		full += " " + client.Os.Minor
		full += " " + client.Os.Patch
		full += " " + client.Os.PatchMinor
	}
	if client.Device != nil {
		product = client.Device.Family
		full += " " + client.Device.Family

		if product == "Other" {
			product = ""
		}
	}

	return &userAgent{
		client:  client,
		product: product,
		vendor:  vendor,
		version: version,
		full:    strings.TrimSpace(full),
	}
}

// generic version harvester, scans the payload using a regular expression
func softwareHarvester(data []byte, ident string, ts time.Time, service string, dpIdent string, protos []string) (software []*Software) {

	var s []*Software

	matches := reGenericVersion.FindAll(data, -1)

	if len(matches) > 0 {
		for _, v := range matches {
			s = append(s, &Software{
				Software: &types.Software{
					Notes: string(v),
				},
			})
		}
	}

	return s
}

// tries to determine the kind of software and version
// based on the provided input data
func whatSoftware(dp *DeviceProfile, i *packetInfo, f, serviceNameSrc, serviceNameDst, JA3, JA3s, userAgents, serverNames string, protos []string, vias string, xPoweredBy string, CMSHeaders []HeaderForApps, CMSCookies []CookieForApps) (software []*Software) {

	var (
		service string
		s       []*Software
		dpIdent = dp.MacAddr
	)
	if serviceNameSrc != "" {
		service = serviceNameSrc
	}
	if serviceNameDst != "" {
		service = serviceNameDst
	}
	if dp.DeviceManufacturer != "" {
		dpIdent += " <" + dp.DeviceManufacturer + ">"
	}

	// Only do JA3 fingerprinting when both ja3 and ja3s are present, aka when the server Hello is captured
	if len(JA3) > 0 && len(JA3s) > 0 {
		for _, server := range ja3db.Servers {
			serverName := server.Server
			for _, client := range server.Clients {
				clientName := client.Os + "(" + client.Arch + ")"
				for _, process := range client.Processes {
					processName := process.Process
					if process.JA3 == JA3 && process.JA3s == JA3s {
						pMu.Lock()
						var values = regExpServerName.FindStringSubmatch(serverName)
						s = append(s, &Software{
							Software: &types.Software{
								Timestamp:      i.timestamp,
								Product:        values[1], // Name of the server (Apache, Nginx, ...)
								Vendor:         values[3], // Unfitting name, but operating system
								Version:        values[2], // Version as found after the '/'
								DeviceProfiles: []string{dpIdent},
								SourceName:     "JA3s",
								SourceData:     JA3s,
								Service:        service,
								DPIResults:     protos,
								Flows:          []string{f},
							},
						})
						s = append(s, &Software{
							Software: &types.Software{
								Timestamp:      i.timestamp,
								Product:        processName, // Name of the browser, including version
								Vendor:         clientName,  // Name of the OS
								Version:        "",          // TODO parse client name
								DeviceProfiles: []string{dpIdent},
								SourceName:     "JA3",
								SourceData:     JA3,
								Service:        service,
								DPIResults:     protos,
								Flows:          []string{f},
							},
						})
						pMu.Unlock()
					}
				}
			}
		}
	}

	// if nothing was found with all above attempts, try to throw the generic version number harvester at it
	// and see if this delivers anything interesting

	var hassh string = "00d352967f27037847ef46466c07c06b"
	if len(hassh) > 0 {
		if fingerprint, ok := hasshMap[hassh]; ok {
			for _, soft := range fingerprint {
				s = append(s, &Software{
					Software: &types.Software{
						Version: soft.Version,
						Notes:   "Likelyhood: " + soft.Likelyhood,
					},
				})
			}
		}
	}

	if len(s) == 0 {
		return softwareHarvester(i.p.Data(), dpIdent, i.p.Metadata().CaptureInfo.Timestamp, service, dpIdent, protos)
	}

	// Defining the variable here to avoid errors. This should be passed as a parameter and contain the hassh value
	return s
}

func whatSoftwareHTTP(dp *DeviceProfile, f, serviceNameSrc, serviceNameDst string, h *types.HTTP, CMSHeaders []HeaderForApps, CMSCookies []CookieForApps) (software []*Software) {

	var (
		service string
		s       []*Software
		//dpIdent = dp.MacAddr
	)
	if serviceNameSrc != "" {
		service = serviceNameSrc
	}
	if serviceNameDst != "" {
		service = serviceNameDst
	}
	// if dp.DeviceManufacturer != "" {
	// 	dpIdent += " <" + dp.DeviceManufacturer + ">"
	// }

	// HTTP User Agents
	// TODO: check for userAgents retrieved by Ja3 lookup as well
	// TODO: Don't iterate
	for _, ua := range strings.Split(h.UserAgent, "| ") {
		if len(ua) == 0 || ua == " " {
			continue
		}
		pMu.Lock()
		userInfo, ok := userAgentCaching[ua]
		if !ok {
			userInfo = parseUserAgent(ua)
			userAgentCaching[ua] = userInfo
			utils.DebugLog.Println("UserAgent:", userInfo.full)
		}
		pMu.Unlock()

		s = append(s, &Software{
			Software: &types.Software{
				Timestamp: h.Timestamp,
				Product:   userInfo.product,
				Vendor:    userInfo.vendor,
				Version:   userInfo.version,
				//DeviceProfiles: []string{dpIdent},
				SourceName: "UserAgent",
				SourceData: ua,
				Service:    service,
				Flows:      []string{f},
				Notes:      userInfo.full,
			},
		})
	}

	// HTTP Server Name
	for _, sn := range strings.Split(h.ServerName, "| ") {
		if len(sn) == 0 || sn == " " {
			continue
		}
		var values = regExpServerName.FindStringSubmatch(sn)
		s = append(s, &Software{
			Software: &types.Software{
				Timestamp: h.Timestamp,
				Product:   values[1], // Name of the server (Apache, Nginx, ...)
				Vendor:    values[3], // Unfitting name, but operating system
				Version:   values[2], // Version as found after the '/'
				//DeviceProfiles: []string{dpIdent},
				SourceName: "ServerName",
				SourceData: sn,
				Service:    service,
				Flows:      []string{f},
			},
		})
	}

	// X-Powered-By HTTP Header
	for _, pb := range strings.Split(h.RequestHeader["X-Powered-By"], "| ") {
		if len(pb) == 0 || pb == " " {
			continue
		}

		var values = regexpXPoweredBy.FindStringSubmatch(pb)
		s = append(s, &Software{
			Software: &types.Software{
				Timestamp: h.Timestamp,
				Product:   values[1], // Name of the server (Apache, Nginx, ...)
				Version:   values[2], // Version as found after the '/'
				//DeviceProfiles: []string{dpIdent},
				SourceName: "X-Powered-By",
				SourceData: pb,
				Service:    service,
				Flows:      []string{f},
			},
		})
	}

	// Try to detect apps
	if receivedHeaders, ok := httpStore.CMSHeaders[h.DstIP]; ok {
		for k, v := range cmsDB {
			if headers, ok := v.(map[string]interface{}); ok {
				if hdrs, ok := headers["headers"]; ok {
					for key, val := range hdrs.(map[string]interface{}) {
						for _, receivedHeader := range receivedHeaders {
							re, err := regexp.Compile(val.(string))
							if err != nil {
								fmt.Println("Failed to compile:    " + val.(string))
							} else {
								if strings.ToLower(receivedHeader.HeaderName) == strings.ToLower(key) && (re.MatchString(receivedHeader.HeaderValue) || val == "") {
									s = append(s, &Software{
										Software: &types.Software{
											Timestamp:  h.Timestamp,
											Product:    k,
											Version:    "",
											SourceName: key,
											Service:    service,
											Flows:      []string{f},
										},
									})
								}
							}
						}
					}
				}
			}
		}
	}

	// Defining the variable here to avoid errors. This should be passed as a parameter and contain the hassh value
	return s
}

// AnalyzeSoftware tries to identify software based on observations from the data
// this function first gathers as much data as possible and then calls into whatSoftware
// to determine what software the packet belongs to
func AnalyzeSoftware(i *packetInfo) {

	var (
		serviceNameSrc, serviceNameDst string
		ja3Hash                        = ja3.DigestHexPacket(i.p)
		JA3s                           string
		JA3                            string
		protos                         []string
		userAgents, serverNames        string
		f                              string
		vias                           string
		xPoweredBy                     string
		cmsHeaders                     []HeaderForApps
		cmsCookies                     []CookieForApps
	)
	if ja3Hash == "" {
		ja3Hash = ja3.DigestHexPacketJa3s(i.p)
	}

	// Lookup Service For Port Numbers
	if tl := i.p.TransportLayer(); tl != nil {

		// set flow ident
		f = i.srcIP + ":" + tl.TransportFlow().Src().String() + "->" + i.dstIP + ":" + tl.TransportFlow().Dst().String()

		// get source port and convert to integer
		src, err := strconv.Atoi(tl.TransportFlow().Src().String())
		if err == nil {
			switch tl.LayerType() {
			case layers.LayerTypeTCP:
				serviceNameSrc = resolvers.LookupServiceByPort(src, "tcp")
			case layers.LayerTypeUDP:
				serviceNameSrc = resolvers.LookupServiceByPort(src, "udp")
			default:
			}
		}
		dst, err := strconv.Atoi(tl.TransportFlow().Dst().String())
		if err == nil {
			switch tl.LayerType() {
			case layers.LayerTypeTCP:
				serviceNameDst = resolvers.LookupServiceByPort(dst, "tcp")
			case layers.LayerTypeUDP:
				serviceNameDst = resolvers.LookupServiceByPort(dst, "udp")
			default:
			}
		}
	} else {

		// no transport layer
		f = i.srcIP + "->" + i.dstIP
	}

	// Deep Packet Inspection
	results := dpi.GetProtocols(i.p)
	for p := range results {
		protos = append(protos, p)
	}

	// Check available HTTP meta infos
	httpStore.Lock()
	if val, ok := httpStore.UserAgents[i.srcIP]; ok {
		userAgents = val
	}
	if val, ok := httpStore.ServerNames[i.dstIP]; ok {
		serverNames = val
	}
	if val, ok := httpStore.Vias[i.dstIP]; ok {
		vias = val
	}
	if val, ok := httpStore.XPoweredBy[i.dstIP]; ok {
		xPoweredBy = val
	}
	if val, ok := httpStore.CMSHeaders[i.dstIP]; ok {
		cmsHeaders = val
	}
	if val, ok := httpStore.CMSCookies[i.dstIP]; ok {
		cmsCookies = val
	}
	httpStore.Unlock()

	// The underlying assumption is that we will always observe a client TLS Hello before seeing a server TLS Hello
	// Assuming the packet captured corresponds to the server Hello, first try to see if a client Hello (client being the
	// destination IP) was observed. If not, this is the client. Therefore add client ja3 signature to the store.
	if len(ja3Hash) > 0 {
		var ok bool
		jaCacheMutex.Lock()
		JA3, ok = ja3Cache[i.dstIP]
		jaCacheMutex.Unlock()
		if !ok {
			jaCacheMutex.Lock()
			ja3Cache[i.srcIP] = ja3Hash
			jaCacheMutex.Unlock()
			JA3 = ""
			JA3s = ""
		} else {
			JA3s = ja3Hash
		}
	}

	// fetch the associated device profile
	dp := getDeviceProfile(i.srcMAC, i)

	// now that we have some information at hands
	// try to determine what kind of software it is
	software := whatSoftware(dp, i, f, serviceNameSrc, serviceNameDst, JA3, JA3s, userAgents, serverNames, protos, vias, xPoweredBy, cmsHeaders, cmsCookies)
	if len(software) == 0 {
		return
	}

	// add new audit records or update existing
	SoftwareStore.Lock()
	for _, s := range software {
		if p, ok := SoftwareStore.Items[s.Product+"/"+s.Version]; ok {
			updateSoftwareAuditRecord(dp, p, i)
		} else {
			SoftwareStore.Items[s.Product+"/"+s.Version] = s
			statsMutex.Lock()
			reassemblyStats.numSoftware++
			statsMutex.Unlock()
		}
	}
	SoftwareStore.Unlock()
}

// NewDeviceProfile creates a new device specific profile
func NewSoftware(i *packetInfo) *Software {
	return &Software{
		Software: &types.Software{
			Timestamp: i.timestamp,
		},
	}
}

func updateSoftwareAuditRecord(dp *DeviceProfile, p *Software, i *packetInfo) {

	var (
		dpIdent = dp.MacAddr
	)
	if dp.DeviceManufacturer != "" {
		dpIdent += " <" + dp.DeviceManufacturer + ">"
	}

	p.Lock()
	for _, pr := range p.DeviceProfiles {
		if pr == dpIdent {
			p.Unlock()
			return
		}
	}
	p.DeviceProfiles = append(p.DeviceProfiles, dpIdent)
	tl := i.p.TransportLayer()
	if tl != nil {
		p.Flows = append(p.Flows, i.srcIP+":"+tl.TransportFlow().Src().String()+"->"+i.dstIP+":"+tl.TransportFlow().Dst().String())
	} else {
		// no transport layer
		p.Flows = append(p.Flows, i.srcIP+"->"+i.dstIP)
	}
	p.Unlock()
}

var softwareEncoder = CreateCustomEncoder(types.Type_NC_Software, "Software", func(d *CustomEncoder) error {

	if errInitUAParser != nil {
		return errInitUAParser
	}

	// Load the JSON database of JA3/JA3S combinations into memory
	data, err := ioutil.ReadFile("/usr/local/etc/netcap/dbs/ja_3_3s.json")
	if err != nil {
		return err
	}

	// unpack JSON
	err = json.Unmarshal(data, &ja3db.Servers)
	if err != nil {
		return err
	}

	// Load the JSON database of HASSH signaures
	data, err = ioutil.ReadFile("/usr/local/etc/netcap/dbs/hasshdb_full.json")
	if err != nil {
		return err
	}

	// unpack JSON
	err = json.Unmarshal(data, &hasshDB)
	if err != nil {
		return err
	}

	data, err = ioutil.ReadFile("/usr/local/etc/netcap/dbs/cmsdbTest.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &cmsDB)
	if err != nil {
		return err
	}

	for _, entry := range hasshDB {
		hasshMap[entry.Hash] = entry.Softwares // Holds redundant info, but couldn't figure a more elegant way to do this
	}

	utils.DebugLog.Println("loaded Ja3/ja3S database, records:", len(ja3db.Servers))

	return nil
}, func(p gopacket.Packet) proto.Message {

	// handle packet
	AnalyzeSoftware(newPacketInfo(p))

	return nil
}, func(e *CustomEncoder) error {

	httpStore.Lock()
	var rows [][]string
	for ip, ua := range httpStore.UserAgents {
		rows = append(rows, []string{ip, ua})
	}
	tui.Table(utils.DebugLogFileHandle, []string{"IP", "UserAgents"}, rows)
	rows = [][]string{}
	for ip, sn := range httpStore.ServerNames {
		rows = append(rows, []string{ip, sn})
	}
	tui.Table(utils.DebugLogFileHandle, []string{"IP", "ServerNames"}, rows)
	httpStore.Unlock()

	// teardown DPI C libs
	dpi.Destroy()

	// flush writer
	if !e.writer.IsChanWriter {
		for _, c := range SoftwareStore.Items {
			c.Lock()
			e.write(c.Software)
			c.Unlock()
		}
	}
	return nil
})

// TODO: move into CustomEncoder and use in other places to remove unnecessary package level encoders
// writeProfile writes the profile
func (e *CustomEncoder) write(c types.AuditRecord) {

	if e.export {
		c.Inc()
	}

	atomic.AddInt64(&e.numRecords, 1)
	err := e.writer.Write(c.(proto.Message))
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
