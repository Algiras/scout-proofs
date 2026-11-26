{{- /* SPDX-License-Identifier: Apache-2.0 */ -}}
{{- define "scout.fullname" -}}{{ .Release.Name }}-scout{{- end -}}
{{- define "scout.labels" -}}
app.kubernetes.io/name: scout
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "scout.secretName" -}}{{ default (printf "%s-secrets" (include "scout.fullname" .)) .Values.secrets.existingSecret }}{{- end -}}
{{- define "scout.brokerUrl" -}}
{{- if .Values.broker.publicBaseUrl -}}{{ .Values.broker.publicBaseUrl }}{{- else -}}http://{{ include "scout.fullname" . }}-broker.{{ .Release.Namespace }}.svc:{{ .Values.broker.port }}{{- end -}}
{{- end -}}
{{- define "scout.providerHost" -}}{{ include "scout.fullname" . }}-mockprovider.{{ .Release.Namespace }}.svc{{- end -}}
{{- define "scout.image" -}}{{ .Values.image.repository }}:{{ .Values.image.tag }}{{- end -}}
{{- define "scout.podSecurity" -}}
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
{{- end -}}
{{- define "scout.containerSecurity" -}}
securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
{{- end -}}
