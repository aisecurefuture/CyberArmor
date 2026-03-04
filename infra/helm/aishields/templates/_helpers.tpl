{{/*
Expand the name of the chart.
*/}}
{{- define "aishields.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec). If release name contains chart name it will be used
as a full name.
*/}}
{{- define "aishields.fullname" -}}
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
{{- define "aishields.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "aishields.labels" -}}
helm.sh/chart: {{ include "aishields.chart" . }}
{{ include "aishields.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aishields
{{- end }}

{{/*
Selector labels
*/}}
{{- define "aishields.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aishields.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "aishields.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "aishields.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Component-specific labels helper.
Usage: {{ include "aishields.componentLabels" (dict "component" "control-plane" "context" $) }}
*/}}
{{- define "aishields.componentLabels" -}}
helm.sh/chart: {{ include "aishields.chart" .context }}
app.kubernetes.io/name: {{ include "aishields.name" .context }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- if .context.Chart.AppVersion }}
app.kubernetes.io/version: {{ .context.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .context.Release.Service }}
app.kubernetes.io/part-of: aishields
{{- end }}

{{/*
Component-specific selector labels helper.
Usage: {{ include "aishields.componentSelectorLabels" (dict "component" "control-plane" "context" $) }}
*/}}
{{- define "aishields.componentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "aishields.name" .context }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Image reference helper.
Usage: {{ include "aishields.image" (dict "imageConfig" .Values.controlPlane.image "global" .Values.global "chart" .Chart) }}
*/}}
{{- define "aishields.image" -}}
{{- $tag := default .chart.AppVersion .imageConfig.tag -}}
{{- printf "%s/%s:%s" .global.imageRegistry .imageConfig.repository $tag -}}
{{- end }}

{{/*
Namespace helper - returns the configured namespace.
*/}}
{{- define "aishields.namespace" -}}
{{- default .Release.Namespace .Values.global.namespace }}
{{- end }}
