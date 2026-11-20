{{- define "portal-tunnel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "portal-tunnel.fullname" -}}
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

{{- define "portal-tunnel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "portal-tunnel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "portal-tunnel.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "portal-tunnel.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "portal-tunnel.secretName" -}}
{{- .Values.existingSecret | default (include "portal-tunnel.fullname" .) }}
{{- end }}

{{/* The identity lives on a volume only when no identity Secret is given. */}}
{{- define "portal-tunnel.persistent" -}}
{{- and .Values.persistence.enabled (not .Values.identity.existingSecret) }}
{{- end }}

{{- define "portal-tunnel.validate" -}}
{{- if not (or .Values.target .Values.args) }}
{{- fail "set target, or args that select what to expose" }}
{{- end }}
{{- /* The relay rejects an unnamed HTTP service unless it uses Local TLS or a raw port. */}}
{{- $unnamedAllowed := false }}
{{- range .Values.args }}
{{- if regexMatch "^--?(name|tcp|udp|tls-auto|tls-cert)(=|$)" (toString .) }}
{{- $unnamedAllowed = true }}
{{- end }}
{{- end }}
{{- range $key := list "TCP_ENABLED" "UDP_ENABLED" }}
{{- if has (lower (toString (get $.Values.env $key))) (list "1" "t" "true") }}
{{- $unnamedAllowed = true }}
{{- end }}
{{- end }}
{{- if not (or (trim (toString .Values.name)) $unnamedAllowed) }}
{{- fail "set name: the relay rejects an unnamed HTTP service unless args select --tcp, --udp, --tls-auto or --tls-cert" }}
{{- end }}
{{- if and (gt (int .Values.replicaCount) 1) (not .Values.identity.existingSecret) }}
{{- fail "replicaCount above 1 needs identity.existingSecret: replicas serve one URL only with one identity" }}
{{- end }}
{{- if and .Values.secretEnv .Values.existingSecret }}
{{- fail "set secretEnv or existingSecret, not both" }}
{{- end }}
{{- if hasKey .Values.env "IDENTITY_JSON" }}
{{- fail "pass the identity with identity.existingSecret, not env.IDENTITY_JSON" }}
{{- end }}
{{- if and .Values.metrics.podMonitor.enabled (not .Values.metrics.enabled) }}
{{- fail "metrics.podMonitor needs metrics.enabled" }}
{{- end }}
{{- end }}
