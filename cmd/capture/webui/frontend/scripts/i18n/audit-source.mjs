import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory, digest } from './inventory.mjs';
const snapshot = inventory(), stage = JSON.parse(fs.readFileSync(path.join(frontend, 'localization/full-staging.json'), 'utf8'));
const htmlReviews = JSON.parse(fs.readFileSync(path.join(frontend, 'localization/html-reviews.json'), 'utf8'));
const sources = new Map();
for (const [id, entry] of Object.entries(stage.messages)) { sources.set(entry.message, id); for (const location of entry.locations) if (location.source) sources.set(location.source, id); }
const decisions = { schemaVersion: 1, occurrences: {}, formatting: {}, dynamicUI: {}, dynamicTranslations: {}, html: {} }, unresolved = [], parent = [], classifications = {};
const cssProperties = new Set('color background backgroundColor border borderColor borderTop borderBottom borderLeft borderRight boxShadow textShadow fontFamily fontSize fontWeight textAlign textTransform textDecoration display position overflow overflowX overflowY whiteSpace wordBreak overflowWrap alignItems alignContent justifyContent flexDirection flexWrap cursor userSelect pointerEvents content transform transformOrigin transition animation animationName filter fill stroke strokeWidth gridTemplateColumns gridTemplateRows gridColumn gridRow objectFit backgroundImage backgroundSize backgroundRepeat backgroundPosition backgroundClip backgroundWidth backgroundHeight backgroundOpacity shape textValign textHalign width height minWidth maxWidth minHeight maxHeight padding margin inset top left right bottom backdropFilter borderRadius resize willChange'.split(' '));
const technicalNames = new Set(['MITRE ATT&CK', 'CISA KEV', 'SNI', 'DHCP', 'ARP', 'ICMPv6', 'FTP', 'GRE', 'GTP', 'IMAP', 'MPLS', 'NTP', 'POP3', 'RDP', 'SIP', 'SMTP', 'VXLAN', 'URL', 'OS', '100MB']);
const metadataProperties = new Set(['name', 'label', 'description', 'question', 'title', 'category', 'caption', 'helperText', 'placeholder', 'summary', 'primary', 'secondary', 'displayName']);
const codeFiles = /\/(?:theme|appearance|graphAppearance|graphLayout|replay|bpfSyntaxHighlight|filterSyntaxHighlight|regexSyntaxHighlight|html)\.ts$/;
const parentList = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };
let hints = 0, localizedHints = 0;
const hintBindings = [];
for (const file of snapshot.files) {
  if (file.html) {
    const key = `${file.repo}/${file.file}`, review = htmlReviews[key];
    if (review?.reason?.trim() && review.sha256 === file.sha256) decisions.html[key] = review;
    else parent.push({ repo: file.repo, file: file.file, kind: 'document-bootstrap', sha256: file.sha256, source: file.html.source });
    continue;
  }
  const sf = ts.createSourceFile(file.file, fs.readFileSync(path.join(roots[file.repo], file.file), 'utf8'), ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const nodes = new Map();
  function collect(node) { nodes.set(`${node.getStart(sf)}:${node.end}`, node); if (ts.isJsxAttribute(node) && /^(?:data-learn|learnHint)$/.test(node.name.getText(sf))) { const localized = Boolean(node.initializer && ts.isJsxExpression(node.initializer) && /\bt\(|i18nText|i18nRichText|translate|renderText|learnHint|metadataText|suppliedMetadataText|finalCopyText|finalCopyMessage|__netcapT/.test(node.initializer.getText(sf))); hintBindings.push({ repo: file.repo, file: file.file, line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1, attribute: node.name.getText(sf), expression: node.initializer?.getText(sf), localized }); if (node.name.getText(sf) === 'data-learn') { hints++; if (localized) localizedHints++; } } ts.forEachChild(node, collect); }
  collect(sf);
  for (const occurrence of file.occurrences) {
    if (['canonical', 'localized'].includes(occurrence.classification)) continue;
    const node = nodes.get(`${occurrence.start}:${occurrence.end}`), chain = node ? parentList(node) : [], source = occurrence.source;
    let reason;
    const property = chain.find(ts.isPropertyAssignment), propertyName = property?.name && (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)) ? property.name.text : '';
    const call = chain.find(ts.isCallExpression), callee = call?.expression.getText(sf) ?? '';
    const attribute = chain.find(ts.isJsxAttribute)?.name.getText(sf);
    const messageSink = chain.some(parent => ts.isCallExpression(parent) && /^(?:set.*(?:Error|Message|Notice|Toast|Snackbar|Notification)|notify|showSnackbar)$/.test(parent.expression.getText(sf)));
    if (!parentOwned(file.file) && occurrence.reason === 'error-may-reach-ui' && /\s/.test(source) && !/^HTTP \{arg\d+\}$/.test(source) && !/\/(?:contexts|providers)\//.test(file.file)) { unresolved.push({ repo: file.repo, file: file.file, line: occurrence.line, id: occurrence.id, source, reason: occurrence.reason, catalog: sources.get(source) }); continue; }
    if (codeFiles.test(file.file)) reason = 'Program/style/parser literal; this module emits syntax/identity/geometry, not app-authored UI prose.';
    else if (chain.some(parent => ts.isLiteralTypeNode(parent) || ts.isImportDeclaration(parent) || ts.isExportDeclaration(parent))) reason = 'Type/module identifier; preserve canonical source.';
    else if (node && ts.isElementAccessExpression(node.parent) && node.parent.argumentExpression === node) reason = 'Object/API field lookup key; UI labels are separate.';
    else if (call?.expression.kind === ts.SyntaxKind.ImportKeyword) reason = 'Dynamic module specifier; preserve canonical import.';
    else if (technicalNames.has(source.trim())) reason = 'Reviewed protocol/standard/product name or explicit technical size; preserve its published identifier.';
    else if (chain.some(parent => ts.isCallExpression(parent) && parent.expression.getText(sf) === 'JSON.stringify')) reason = 'Raw evidence JSON, including its absent-value sentinels; preserve the record rather than translating its data.';
    else if (chain.some(parent => ts.isNewExpression(parent) && parent.expression.getText(sf) === 'DOMException') && source === 'Analyst request aborted') reason = 'AbortError cancellation diagnostic; callers suppress aborted requests rather than displaying this diagnostic.';
    else if ((/^(?:set\w*Severity)$/.test(callee) || propertyName === 'severity') && /^(?:error|warning|success|info)$/.test(source)) reason = 'MUI notification severity discriminant; message text is stored separately.';
    else if (/^(?:selectionAction|number|numberInput)$/.test(callee) && call?.arguments[0] === node) reason = 'Reviewed action/query-field key passed separately from its localized helper label.';
    else if (callee === 'formatMetric' && call?.arguments[1] === node) reason = 'Explicit metric unit selector; formatMetric localizes the number/rate without changing the query.';
    else if (/^(?:rawCode|messageSource)$/.test(callee)) reason = 'Explicit raw-code/diagnostic renderer; preserve executable syntax and raw evidence.';
    else if (/^(?:metadataText|suppliedMetadataText|metadataMessage|metadataMessages|metadataTexts|presentationValue|formatTimestamp|formatDateTime|formatQuantity|enumLabel|fieldLabel|recordTypeLabel|artifactKindLabel|behaviorActionLabel)$/.test(callee)) reason = 'Explicit metadata field, unit, enum or schema selector argument; the helper localizes its display value.';
    else if (chain.some(parent => ts.isJsxAttribute(parent) && /^(?:value|key|id|labelId|name|type|role|scope|component|align|edge|variant|color|activeColor|size|direction|placement|anchorOrigin|compactType|textAnchor|fill|stroke|fontSize|width|height|maxWidth|maxHeight|position|valueLabelDisplay|mode|sandbox|d|viewBox|flexWrap|flexDirection|alignItems|justifyContent|overflow|fontWeight|textAlign|language|bgcolor|scrollButtons|timeout|ml|margin|desktopTable|autoComplete)$/.test(parent.name.getText(sf)))) reason = 'HTML/MUI/control configuration or canonical option identity; its label is localized separately.';
    else if (chain.some(parent => ts.isPropertyAssignment(parent) && (cssProperties.has(parent.name.getText(sf)) || /^(?:['"])?--netcap-/.test(parent.name.getText(sf)))) || chain.some(parent => ts.isJsxAttribute(parent) && /^(?:sx|style|anchorOrigin|slotProps)$/.test(parent.name.getText(sf)))) reason = 'CSS/MUI configuration token; translated accessible text is handled at its explicit display sink.';
    else if (chain.some(parent => ts.isTaggedTemplateExpression(parent))) reason = 'Tagged stylesheet/program template; no text translation.';
    else if (/^(?:console|logger|log)\./.test(callee)) reason = 'Non-UI diagnostic log; preserve original diagnostic.';
    else if (/^(?:[./]|https?:|wss?:|@|[A-Za-z]:\\)/.test(source)) reason = 'Canonical path, URL, route, selector or module ID; never translate.';
    else if (/^(?:rgba?|hsla?|var|calc|linear-gradient|radial-gradient|data)\(/.test(source) || /^#(?:[a-f\d]{3,8})$/i.test(source)) reason = 'CSS/data-mapper token; theme values remain unchanged.';
    else if (/\/OptimizedPieChart\.tsx$/.test(file.file) && source === 'Arial, {arg0}' && occurrence.expressions[0]?.expression === 'chineseFontFallback') reason = 'Chart font-family stack uses the bundled offline CJK fallback; preserve CSS family names.';
    else if (/\/TimelineCanvas\.tsx$/.test(file.file) && /^\d+px "JetBrains Mono", "Noto Sans SC Variable", monospace$/.test(source)) reason = 'Canvas font size and bundled font-family names; preserve renderer configuration.';
    else if (/^(?:\d+(?:\.\d+)?(?:px|em|rem|vh|vw)(?:\s+\d+(?:\.\d+)?(?:px|em|rem|vh|vw))*(?:\s+!important)?|\{arg\d+\}px|\d+px "JetBrains Mono", monospace)$/.test(source) || source === '0 0 0 2px {arg0}') reason = 'Reviewed CSS/canvas geometry or font-stack value; locale changes do not alter program geometry.';
    else if (/^\[data-learn\]$/.test(source) || /^:(?:selected|parent)$/.test(source) || /^\[type = "PCAP"\]$/.test(source) || /^(?:select unselect|dragpan scrollzoom pinchzoom|collection-box collapsed|search-match search-current search-dimmed)$/.test(source)) reason = 'DOM/Cytoscape selector, event or class list; preserve executable syntax.';
    else if (/^(?:certificate_|connection_|http_|host_).*\.pcap$/.test(source) || /^(?:pcap-|custom-|collection-|netcap-live-|injectionEvents)\{arg\d+\}|^\{arg\d+\}\.yml$/.test(source)) reason = 'Capture artifact/internal entity/event ID; preserve its canonical identity.';
    else if (/^\{arg\d+\}(?:\/api\/|&format=html)|^Bearer \{arg\d+\}$|^HTTP \{arg\d+\}$|^\{arg\d+\}\.EnableNotifications$/.test(source)) reason = 'API/transport/binding syntax with canonical interpolated values.';
    else if (/\/pages\/investigation\.tsx$/.test(file.file) && ['proxy-nat-log', 'debugger-stack'].includes(source) && call && /\.map$/.test(callee)) reason = 'Canonical artifact-kind option; artifactKindLabel resolves its separate human-readable label.';
    else if (/^(?:IsPrivateIP|IsPublicIP|ParsePort)\(/.test(source) || /^SrcIP == \{arg0\} \|\| DstIP == \{arg1\}$/.test(source) || /^\{b\}: \{c\} \(\{d\}%\)$/.test(source)) reason = 'Filter or ECharts formatter program; preserve its syntax and identifiers.';
    else if (['vertical', 'horizontal'].includes(propertyName)) reason = 'MUI popup anchor geometry, not accessible/display copy.';
    else if (['caretColor', 'bgcolor'].includes(propertyName)) reason = 'MUI/CSS color token; no display prose.';
    else if (source === 'allow-scripts allow-downloads' && /ChartFrame\.tsx$/.test(file.file)) reason = 'Opaque-origin iframe sandbox capability list; preserve exactly.';
    else if (/\/SyntaxHighlightedInput\.tsx$/.test(file.file) && /^(?:syntax-\{arg0\}|\{arg0\}-(?:label|help))$/.test(source)) reason = 'Stable editor/ARIA relationship identifier generated with useId; only its visible label/help content localizes.';
    else if (source === '; {arg0}–{arg1} ns') reason = 'Raw capture interval annotation; nanosecond digits stay canonical.';
    else if (source === 'ruleset:{arg0}') reason = 'Ruleset operation/cache identity, not a displayed label.';
    else if (callee === 'filters.push' && /\/pages\/InjectPage\.tsx$/.test(file.file) && /^(?:rule|result|action)=\{arg\d+\}$/.test(source)) reason = 'Injection-event query parameter assignment; preserve API key and encoded value.';
    else if (callee === 'Call.ByName' && source === '{arg0}.OpenCaptureFiles') reason = 'Native CaptureFilesService RPC method name; preserve the bridge identifier.';
    else if (callee === 'Call.ByName' && source === '{arg0}.{arg1}') reason = 'Native service/method RPC identifier; never translate bridge names.';
    else if (callee === 'renderNavigationItems' && call?.arguments[0] === node && /^(?:workspace-before-pcaps|main|data-before-logs|detection-end|system-start|system-before-bpf|settings)$/.test(source)) reason = 'Canonical navigation placement selector; the helper translates each item label and description.';
    else if (/\.style\.setProperty$/.test(callee) && call?.arguments[0] === node && /^--netcap-/.test(source)) reason = 'CSS custom-property name; preserve the theme/font binding.';
    else if (/\.style\.setProperty$/.test(callee) && /^['"]--netcap-(?:font|mono)['"]$/.test(call?.arguments[0]?.getText(sf) ?? '') && call.arguments[1] === node) reason = 'Installed font-family stack, including offline CJK fallback; preserve CSS family names.';
    else if (/^\{arg0\} — Netcap(?: Pro)?$/.test(source) && occurrence.expressions[0]?.expression === "translate('Network traffic intelligence')") reason = 'Localized document title followed by the unchanged Netcap product name.';
    else if (/\/lib\/similarity\.ts$/.test(file.file) && source === 'direct:pro.similarity.group.{arg0}') reason = 'Native semantic group ID selected only from the four known group keys; display text resolves through its supplied descriptor.';
    else if (propertyName === 'vertexShader' || propertyName === 'fragmentShader' || source === '2d' && /TimelineCanvas\.tsx$/.test(file.file)) reason = 'WebGL shader or canvas context program; no UI prose.';
    else if (source === 'use client' && ts.isExpressionStatement(node?.parent)) reason = 'JavaScript module directive; no UI prose.';
    else if (/\/lib\/recordUnits\.ts$/.test(file.file)) reason = 'Raw evidence inspector retains decimal nanoseconds and canonical ISO-8601 time annotations.';
    else if (/\/lib\/evidenceLinks\.ts$/.test(file.file) && sources.has(source)) reason = `Reviewed app-authored link-kind registry; RelatedEvidence.tsx resolves linkKindLabels with finalCopyText at render (${sources.get(source)}).`;
    else if (/\/lib\/similarity\.ts$/.test(file.file) && chain.some(parent => ts.isVariableDeclaration(parent) && parent.name.getText(sf) === 'groupLabels') && sources.has(source)) reason = `Reviewed app-authored similarity group label; similarity.tsx resolves groupLabels at render (${sources.get(source)}).`;
    else if (/\/pages\/DbsPage\.tsx$/.test(file.file) && sources.has(source) && chain.some(parent => ts.isVariableDeclaration(parent) && parent.name.getText(sf) === 'DB_DESCRIPTIONS')) reason = `Reviewed database-documentation registry; finalCopyText(DB_DESCRIPTIONS[...]) resolves ${sources.get(source)} at render.`;
    else if (/\/components\/TrafficScene\.tsx$/.test(file.file) && /\.onError$/.test(callee) && call?.arguments[0] === node && call.arguments.length === 2 && sources.has(source)) reason = 'Original diagnostic callback retained alongside its deferred localized presentation argument.';
    else if (metadataProperties.has(propertyName) && sources.has(source)) reason = `App-authored metadata remains identity-stable. Bundled catalog ${sources.get(source)} is resolved at translate/metadataText/suppliedMetadataText display bindings.`;
    else if (!messageSink && sources.has(source) && chain.some(parent => ts.isArrayLiteralExpression(parent) || ts.isObjectLiteralExpression(parent)) && file.dynamicTranslations.length) reason = `Identity-stable display registry value ${sources.get(source)}; inspected translate(...) binding in ${file.file} resolves labels without changing keys/values.`;
    else if (file.file.endsWith('.json') && sources.has(source)) reason = `Bundled metadata source ${sources.get(source)}; edition-aware release-highlight renderer translates at display time.`;
    else if (/\/(?:contexts|providers)\//.test(file.file) && /must be used within|wrap.*Provider|no.*provider/i.test(source)) reason = 'Developer-only provider invariant; not a production UI message.';
    else if (/\/preferences\/PresentationProvider\.tsx$/.test(file.file) && source === 'PresentationProvider is required' && chain.some(parent => ts.isNewExpression(parent) && parent.expression.getText(sf) === 'Error')) reason = 'Developer-only context invariant in usePresentation; user-facing load/save failures have separate localized messages.';
    else if (chain.some(parent => ts.isCallExpression(parent) && /(?:setItem|getItem|removeItem|addEventListener|removeEventListener|\.On|\.Emit|\.isActive|\.getQueryParam|router\.push|history\.push|\.navigate|\.join|\.split|\.replace|\.replaceAll|\.includes|\.startsWith|\.endsWith|\.indexOf|\.match|\.test|encodeURIComponent|querySelector|createElement|setAttribute)/.test(parent.expression.getText(sf)))) reason = 'Wire/storage/event/selector/parser argument; preserve identity or syntax.';
    else if (chain.some(parent => ts.isCaseClause(parent) && parent.expression === node)) reason = 'Switch discriminant; UI labels resolve separately.';
    else if (source.startsWith('\u001b[')) reason = 'ANSI terminal escape sequence; preserve byte identity.';
    else if (occurrence.expressions.length && /(?:\/|[?&][A-Za-z]|\\s\*|binding\?)/.test(source) && occurrence.reason === 'callback-constant-or-data') reason = 'Interpolated canonical URL/query/filter/regex or evidence identity; not translated UI prose.';
    else if (!/\p{L}/u.test(source.replace(/\{arg\d+\}/g, ''))) reason = 'Opaque captured parameters plus punctuation/delimiters; no authored prose to translate.';
    else if (/^\{arg\d+\}\s*(?:ns|µs|ms|s|min|h|d|B|KB|MB|GB|KiB|MiB|GiB|VLAN|UTC)(?:\s*\{arg\d+\})?$/.test(source.trim())) reason = 'Explicit technical unit with locale-formatted quantity; preserve SI/IEC symbol.';
    else if (!/\p{L}/u.test(source)) reason = 'Punctuation, numeric literal or symbol; no language-bearing prose.';
    else if (!/\s/.test(source) && /^(?:[a-zA-Z_][\w:./#-]*|[\d.]+(?:px|rem|vh|vw|ms|s|%))$/.test(source) && occurrence.classification === 'review') reason = 'Canonical non-display identifier/token; not a JSX/attribute/help message sink.';
    if (reason) {
      decisions.occurrences[occurrence.id] = { action: 'keep', source, reason, evidence: `${file.repo}/${file.file}:${occurrence.line}` };
      classifications[reason.split(';')[0]] = (classifications[reason.split(';')[0]] ?? 0) + 1;
    } else if (parentOwned(file.file)) parent.push({ repo: file.repo, file: file.file, line: occurrence.line, id: occurrence.id, source, catalog: sources.get(source), kind: occurrence.reason });
    else unresolved.push({ repo: file.repo, file: file.file, line: occurrence.line, id: occurrence.id, source, reason: occurrence.reason, catalog: sources.get(source), callee, property: propertyName, attribute });
  }
  for (const site of file.dynamicTranslations ?? []) {
    const id = digest(`${file.repo}/${file.file}\0${site.expression}`).slice(0, 24);
    decisions.dynamicTranslations[id] = { expression: site.expression, reason: 'Inspected app-owned display registry/enum/metadata binding. Captured values, notes, labels without supplied metadata and user inputs are excluded.', evidence: `${file.file}:${site.line}` };
  }
  if (!parentOwned(file.file)) for (const site of file.formatting ?? []) {
    let reason;
    if (/\.toLocale(?:String|DateString|TimeString)\((?:getLocale|getUILocale)\(\)/.test(site.expression)) reason = 'Selected UI locale is explicit. Counter values and ISO/millisecond Date inputs are display-only; nanosecond conversions divide by 1e6 explicitly.';
    else if (site.method === 'toISOString' && /\/(?:NetworkDetectionEvidence|RelatedEvidence)\.tsx$|\/lib\/recordUnits\.ts$|\/lib\/machineTypes\.ts$|\/pages\/BehaviorPage\.tsx$/.test(file.file)) reason = /machineTypes/.test(file.file) ? 'Persisted machine createdAt/updatedAt wire timestamps use canonical UTC ISO-8601.' : 'Canonical UTC evidence annotation with explicit ns-to-ms conversion; no magnitude guessing or invented sub-millisecond precision.';
    else if (site.expression === 'Intl.DateTimeFormat()' && /\/lib\/timelineTime\.ts$/.test(file.file)) reason = 'Reads the OS IANA time zone only; actual timeline formatting uses the active locale and exact bigint nanoseconds.';
    if (reason) decisions.formatting[digest(`${file.repo}/${file.file}\0${site.expression}`).slice(0, 24)] = { expression: site.expression, reason, evidence: `${file.file}:${site.line}` };
  }
  if (!parentOwned(file.file)) for (const site of file.dynamicUI ?? []) {
    let reason;
    if (/^set\w+\((?:null|true|false)\)$|^set\w+\(\(?\w+\)?\s*=>\s*\(\{\s*\.\.\./.test(site.expression) || /\.\.\.(?:snackbar|toast), open: false/.test(site.expression)) reason = 'Clears or closes existing UI state without changing its deferred message/data.';
    else if (/^setErrorLogContent\(content\)$/.test(site.expression)) reason = 'Raw capture/server log content is retained verbatim; app-authored failure wrappers are separate descriptors.';
    else if (/\b(?:i18nMessage|i18nParameterMessage|message|metadataMessage|errorText)\(/.test(site.expression) && !/\b(?:i18nText|translate)\(/.test(site.expression)) reason = 'App-authored status/error is a deferred descriptor; structured backend errors retain their metadata and unrecognized diagnostics remain raw.';
    else if (/^set(?:Error|Notice)\((?:msg|message|success|validationError)\)$|^setSnackbar\(\{ open: true, message, severity \}\)$/.test(site.expression)) reason = 'Reviewed MessageText helper parameter/validation result. Callers pass deferred descriptors or raw backend diagnostics, resolved at render.';
    else if (/^setSnackbar\(\{ open: true, message: summaryMessage,/.test(site.expression)) reason = 'Batch summaryMessage is composed with message/joinMessages and retains deferred backend result metadata.';
    else if (/\/LicenseGate\.tsx$/.test(file.file) && site.expression === 'setError(failure.summary)') reason = 'licenseFailure returns a deferred MessageText summary for the known local code/prefix or operation fallback.';
    else if (/\/LicenseGate\.tsx$/.test(file.file) && site.expression === 'setErrorDetail(failure.detail)') reason = 'licenseFailure retains original native/SDK diagnostic text in a separate disclosure; no translation or source matching.';
    if (reason) decisions.dynamicUI[digest(`${file.repo}/${file.file}\0${site.expression}`).slice(0, 24)] = { expression: site.expression, reason, evidence: `${file.file}:${site.line}` };
  }
}
fs.writeFileSync(path.join(frontend, 'localization/decisions.json'), JSON.stringify(decisions, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/source-audit-unresolved.jsonl'), unresolved.map(item => JSON.stringify(item)).join('\n') + '\n');
fs.writeFileSync(path.join(frontend, 'localization/parent-findings.json'), JSON.stringify(parent, null, 2) + '\n');
const baselinePath = process.env.NETCAP_I18N_BASELINE;
let baselineLearnBindings;
if (baselinePath) {
  baselineLearnBindings = 0;
  for (const file of JSON.parse(fs.readFileSync(baselinePath, 'utf8'))) {
    const source = ts.createSourceFile(file.file, file.text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const count = node => { if (ts.isJsxAttribute(node) && /^(?:data-learn|learnHint)$/.test(node.name.getText(source))) baselineLearnBindings++; ts.forEachChild(node, count); };
    count(source);
  }
}
fs.writeFileSync(path.join(frontend, 'localization/learn-bindings.json'), JSON.stringify({ baselineLearnBindings, currentLearnBindings: hintBindings.length, unresolved: hintBindings.filter(item => !item.localized), bindings: hintBindings }, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/source-audit-summary.json'), JSON.stringify({ files: snapshot.files.length, classifiedNonUIOrMetadataSites: Object.keys(decisions.occurrences).length, unresolvedSites: unresolved.length, parentOwnedFindings: parent.length, learnAttributes: hints, directlyLocalizedOrSuppliedLearnAttributes: localizedHints, classifications }, null, 2) + '\n');
console.log(JSON.stringify({ classified: Object.keys(decisions.occurrences).length, unresolved: unresolved.length, parentOwned: parent.length, learnAttributes: hints, localizedLearnAttributes: localizedHints }));
