{{/*
Expand the name of the chart.
*/}}
{{- define "cyberarmor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec). If release name contains chart name it will be used
as a full name.
*/}}
{{- define "cyberarmor.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cyberarmor.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cyberarmor.labels" -}}
helm.sh/chart: {{ include "cyberarmor.chart" . }}
{{ include "cyberarmor.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: cyberarmor
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cyberarmor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cyberarmor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "cyberarmor.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cyberarmor.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Component-specific labels helper.
Usage: {{ include "cyberarmor.componentLabels" (dict "component" "control-plane" "context" $) }}
*/}}
{{- define "cyberarmor.componentLabels" -}}
helm.sh/chart: {{ include "cyberarmor.chart" .context }}
app.kubernetes.io/name: {{ include "cyberarmor.name" .context }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- if .context.Chart.AppVersion }}
app.kubernetes.io/version: {{ .context.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .context.Release.Service }}
app.kubernetes.io/part-of: cyberarmor
{{- end }}

{{/*
Component-specific selector labels helper.
Usage: {{ include "cyberarmor.componentSelectorLabels" (dict "component" "control-plane" "context" $) }}
*/}}
{{- define "cyberarmor.componentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "cyberarmor.name" .context }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Image reference helper.
Usage: {{ include "cyberarmor.image" (dict "imageConfig" .Values.controlPlane.image "global" .Values.global "chart" .Chart) }}
*/}}
{{- define "cyberarmor.image" -}}
{{- $tag := default .chart.AppVersion .imageConfig.tag -}}
{{- printf "%s/%s:%s" .global.imageRegistry .imageConfig.repository $tag -}}
{{- end }}

{{/*
Namespace helper - returns the configured namespace.
*/}}
{{- define "cyberarmor.namespace" -}}
{{- default .Release.Namespace .Values.global.namespace }}
{{- end }}
