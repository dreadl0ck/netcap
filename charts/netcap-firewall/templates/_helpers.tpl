{{- define "firewall.name" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- define "firewall.selector" -}}
app.kubernetes.io/name: netcap-firewall
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "firewall.labels" -}}
{{ include "firewall.selector" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}
{{- define "firewall.config" -}}
{{- if and .Values.tls.clientCASecretName (not .Values.tls.secretName) }}{{ fail "clientCASecretName requires listener TLS" }}{{- end }}
{{- if and .Values.runtime.crsProfile (not .Values.runtime.corazaCRS) }}{{ fail "crsProfile requires corazaCRS" }}{{- end }}
{{- range .Values.routes }}
{{- if and .crsProfile (not $.Values.runtime.corazaCRS) }}{{ fail "route crsProfile requires corazaCRS" }}{{- end }}
{{- end }}
{{- if .Values.routes }}
{{- if or (eq .Values.mode "fleet") .Values.sharedRate.configSecretName .Values.policyState.configSecretName }}{{ fail "routes do not support fleet, sharedRate or policyState without route-scoped bootstrap bindings" }}{{- end }}
{{- if or (eq .Values.mode "managed") .Values.adminTokenSecret.name .Values.routeID }}
{{- $found := false }}
{{- range .Values.routes }}{{- if eq .id $.Values.routeID }}{{- $found = true }}{{- end }}{{- end }}
{{- if not $found }}{{ fail "routed policy management requires routeID naming one bootstrap route" }}{{- end }}
{{- end }}
{{- else if .Values.routeID }}{{ fail "routeID requires routes" }}
{{- end }}
{{- if and .Values.http3.enabled (not .Values.tls.secretName) }}{{ fail "http3 requires tls.secretName" }}{{- end }}
{{- if ne (empty .Values.sharedRate.configSecretName) (empty .Values.sharedRate.credentialsSecretName) }}{{ fail "sharedRate requires config and credentials Secret references" }}{{- end }}
{{- if ne (empty .Values.policyState.configSecretName) (empty .Values.policyState.credentialsSecretName) }}{{ fail "policyState requires config and credentials Secret references" }}{{- end }}
{{- if and .Values.policyState.configSecretName .Values.sharedRate.configSecretName }}{{ fail "policyState and sharedRate are mutually exclusive" }}{{- end }}
{{- if eq .Values.mode "fleet" }}
{{- if or (not .Values.fleet.configSecretName) (not .Values.fleet.credentialsSecretName) }}{{ fail "fleet mode requires config and credentials Secret references" }}{{- end }}
{{- if .Values.autoscaling.enabled }}{{ fail "fleet mode uses fixed StatefulSet identities; HPA is unsupported" }}{{- end }}
{{- else }}
{{- if or .Values.fleet.configSecretName .Values.fleet.credentialsSecretName }}{{ fail "fleet Secret references require mode=fleet (never managed SQLite)" }}{{- end }}
{{- end }}
{{- if and .Values.adminTokenSecret.name (not .Values.adminTLS.secretName) -}}
{{- fail "adminTokenSecret requires adminTLS.secretName for the network-accessible admin listener" -}}
{{- end -}}
{{- if and .Values.adminService.enabled (not (and .Values.adminTLS.secretName .Values.adminTokenSecret.name)) -}}
{{- fail "adminService requires adminTLS.secretName and adminTokenSecret.name" -}}
{{- end -}}
{{- if and (or .Values.upstreamTLS.caSecretName .Values.upstreamTLS.serverName .Values.upstreamTLS.clientSecretName) (not (hasPrefix "https://" .Values.upstream)) -}}
{{- fail "upstreamTLS options require an https:// upstream" -}}
{{- end -}}
version: netcap-firewall/v1
listen: ':8080'
adminListen: ':9090'
upstream: {{ required "upstream is required" .Values.upstream | quote }}
policyFile: /etc/netcap-firewall/policy.yaml
{{ toYaml .Values.runtime }}
{{- if .Values.routes }}
routes:
{{- $ids := dict }}
{{- range $index, $binding := .Values.routes }}
{{- if hasKey $ids .id }}{{ fail "route IDs must be unique" }}{{- end }}
{{- $_ := set $ids .id true }}
{{- $route := omit . "policy" "upstreamTLS" }}
{{- with .upstreamTLS }}
{{- if and (or .caSecretName .clientSecretName .serverName) (not (hasPrefix "https://" $binding.upstream)) }}{{ fail "route upstreamTLS requires HTTPS" }}{{- end }}
{{- if .caSecretName }}{{- $_ := set $route "upstreamCA" (printf "/etc/netcap-firewall/route-tls/%d/ca/ca.crt" $index) }}{{- end }}
{{- if .serverName }}{{- $_ := set $route "upstreamServerName" .serverName }}{{- end }}
{{- if .clientSecretName }}
{{- $_ := set $route "upstreamCert" (printf "/etc/netcap-firewall/route-tls/%d/client/tls.crt" $index) }}
{{- $_ := set $route "upstreamKey" (printf "/etc/netcap-firewall/route-tls/%d/client/tls.key" $index) }}
{{- end }}
{{- end }}
{{- if and (hasPrefix "https://" .upstream) (not $route.upstreamServerName) }}{{ fail "HTTPS route requires explicit upstreamServerName" }}{{- end }}
{{- $_ := set $route "policyID" .policy.id }}
{{- $_ := set $route "policyFile" (printf "/etc/netcap-firewall/route-%s.yaml" .id) }}
{{ toYaml (list $route) }}
{{- end }}
{{- end }}
{{- if .Values.tls.secretName }}
tlsCert: /etc/netcap-firewall/tls/tls.crt
tlsKey: /etc/netcap-firewall/tls/tls.key
{{- end }}
{{- if .Values.tls.clientCASecretName }}
clientCA: /etc/netcap-firewall/client-ca/ca.crt
{{- end }}
{{- if .Values.upstreamTLS.clientSecretName }}
upstreamCert: /etc/netcap-firewall/upstream-client/tls.crt
upstreamKey: /etc/netcap-firewall/upstream-client/tls.key
{{- end }}
{{- if .Values.upstreamTLS.caSecretName }}
upstreamCA: /etc/netcap-firewall/upstream/ca.crt
{{- end }}
{{- if .Values.upstreamTLS.serverName }}
upstreamServerName: {{ .Values.upstreamTLS.serverName | quote }}
{{- end }}
{{- end -}}
{{- define "firewall.configName" -}}
{{ include "firewall.name" . }}-{{ printf "%s\n%s\n%s" (include "firewall.config" .) (toYaml .Values.policy) (toYaml .Values.routes) | sha256sum | trunc 10 }}
{{- end -}}
{{- define "firewall.probeScheme" -}}
{{- if .Values.adminTLS.secretName -}}HTTPS{{- else -}}HTTP{{- end -}}
{{- end -}}
