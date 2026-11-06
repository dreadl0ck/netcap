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
{{- if and .Values.adminTokenSecret.name (not .Values.adminTLS.secretName) -}}
{{- fail "adminTokenSecret requires adminTLS.secretName for the network-accessible admin listener" -}}
{{- end -}}
{{- if and .Values.adminService.enabled (not (and .Values.adminTLS.secretName .Values.adminTokenSecret.name)) -}}
{{- fail "adminService requires adminTLS.secretName and adminTokenSecret.name" -}}
{{- end -}}
{{- if and (or .Values.upstreamTLS.caSecretName .Values.upstreamTLS.serverName) (not (hasPrefix "https://" .Values.upstream)) -}}
{{- fail "upstreamTLS options require an https:// upstream" -}}
{{- end -}}
version: netcap-firewall/v1
listen: ':8080'
adminListen: ':9090'
upstream: {{ required "upstream is required" .Values.upstream | quote }}
policyFile: /etc/netcap-firewall/policy.yaml
{{ toYaml .Values.runtime }}
{{- if .Values.tls.secretName }}
tlsCert: /etc/netcap-firewall/tls/tls.crt
tlsKey: /etc/netcap-firewall/tls/tls.key
{{- end }}
{{- if .Values.upstreamTLS.caSecretName }}
upstreamCA: /etc/netcap-firewall/upstream/ca.crt
{{- end }}
{{- if .Values.upstreamTLS.serverName }}
upstreamServerName: {{ .Values.upstreamTLS.serverName | quote }}
{{- end }}
{{- end -}}
{{- define "firewall.configName" -}}
{{ include "firewall.name" . }}-{{ printf "%s\n%s" (include "firewall.config" .) (toYaml .Values.policy) | sha256sum | trunc 10 }}
{{- end -}}
{{- define "firewall.probeScheme" -}}
{{- if .Values.adminTLS.secretName -}}HTTPS{{- else -}}HTTP{{- end -}}
{{- end -}}
