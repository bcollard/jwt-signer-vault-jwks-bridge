{{- define "jwks-bridge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "jwks-bridge.fullname" -}}
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

{{- define "jwks-bridge.selectorLabels" -}}
app.kubernetes.io/name: {{ include "jwks-bridge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "jwks-bridge.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "jwks-bridge.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "jwks-bridge.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "jwks-bridge.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "jwks-bridge.keysets" -}}
{{- $pairs := list }}
{{- range $name, $path := .Values.keysets }}
{{- $pairs = append $pairs (printf "%s=%s" $name $path) }}
{{- end }}
{{- join "," $pairs }}
{{- end }}
