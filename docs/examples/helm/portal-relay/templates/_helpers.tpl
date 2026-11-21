{{- define "portal-relay.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "portal-relay.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "portal-relay.selectorLabels" -}}
app.kubernetes.io/name: {{ include "portal-relay.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "portal-relay.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "portal-relay.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "portal-relay.secretName" -}}
{{- .Values.existingSecret | default (include "portal-relay.fullname" .) }}
{{- end }}

{{/* Parses a relay boolean the way strconv.ParseBool accepts true. */}}
{{- define "portal-relay.true" -}}
{{- has (lower (toString .)) (list "1" "t" "true") }}
{{- end }}

{{- define "portal-relay.udp" -}}
{{- include "portal-relay.true" .Values.env.UDP_ENABLED }}
{{- end }}

{{- define "portal-relay.tcp" -}}
{{- include "portal-relay.true" .Values.env.TCP_ENABLED }}
{{- end }}

{{- define "portal-relay.httpRedirect" -}}
{{- include "portal-relay.true" .Values.env.HTTP_REDIRECT_ENABLED }}
{{- end }}

{{- define "portal-relay.embeddedDNS" -}}
{{- has (lower (toString (.Values.env.ACME_DNS_PROVIDER | default ""))) (list "" "embedded") }}
{{- end }}

{{/* Host of PORTAL_URL, with any port removed. */}}
{{- define "portal-relay.host" -}}
{{- (urlParse .Values.env.PORTAL_URL).host | splitList ":" | first }}
{{- end }}

{{/* Public HTTPS port: the PORTAL_URL port, else 443. */}}
{{- define "portal-relay.httpsPort" -}}
{{- $parts := (urlParse .Values.env.PORTAL_URL).host | splitList ":" }}
{{- if eq (len $parts) 2 }}{{ last $parts }}{{ else }}443{{ end }}
{{- end }}

{{- define "portal-relay.validate" -}}
{{- $url := .Values.env.PORTAL_URL | default "" | toString }}
{{- if not (urlParse $url).host }}
{{- fail "env.PORTAL_URL is required and must be an absolute URL such as https://portal.example.com" }}
{{- end }}
{{- range $key := list "SNI_PORT" "EMBEDDED_DNS_PORT" "HTTP_REDIRECT_ADDR" "IDENTITY_PATH" }}
{{- if hasKey $.Values.env $key }}
{{- fail (printf "env.%s is set by the chart; remove it from env" $key) }}
{{- end }}
{{- end }}
{{- if and .Values.secretEnv .Values.existingSecret }}
{{- fail "set secretEnv or existingSecret, not both" }}
{{- end }}
{{- if or (eq (include "portal-relay.udp" .) "true") (eq (include "portal-relay.tcp" .) "true") }}
{{- if not (and .Values.env.MIN_PORT .Values.env.MAX_PORT) }}
{{- fail "UDP_ENABLED and TCP_ENABLED need env.MIN_PORT and env.MAX_PORT for the lease port range" }}
{{- end }}
{{- if gt (int .Values.env.MIN_PORT) (int .Values.env.MAX_PORT) }}
{{- fail "env.MIN_PORT must not exceed env.MAX_PORT" }}
{{- end }}
{{- end }}
{{- if and .Values.podMonitor.enabled (not .Values.existingSecret) (not (hasKey .Values.secretEnv "ADMIN_TOKEN")) }}
{{- fail "podMonitor needs ADMIN_TOKEN in secretEnv or existingSecret" }}
{{- end }}
{{- end }}
