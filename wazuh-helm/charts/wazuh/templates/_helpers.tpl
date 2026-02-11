{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "wazuh.name" -}}
{{- default "wazuh" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "wazuh.fullname" -}}
  {{- if .Values.fullnameOverride -}}
    {{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
  {{- else -}}
    {{- $name := default "wazuh" .Values.nameOverride -}}
    {{- if contains $name .Release.Name -}}
      {{- .Release.Name | trunc 63 | trimSuffix "-" -}}
    {{- else -}}
      {{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
    {{- end -}}
  {{- end -}}
{{- end -}}

{{- define "wazuh.indexer.fullname" -}}
  {{- if .Values.indexer.fullnameOverride -}}
    {{ .Values.indexer.fullnameOverride | trunc 63 | trimSuffix "-" }}
  {{- else -}}
    {{ include "wazuh.fullname" . }}
  {{- end -}}
{{- end -}}

{{- define "wazuh.dashboard.config"}}
server.host: 0.0.0.0
server.port: {{ .Values.dashboard.service.httpPort }}

{{- if .Values.indexer.enabled }}
opensearch.hosts: "https://{{ include "wazuh.indexer.fullname" . }}-indexer:{{ .Values.indexer.service.httpPort }}"
{{- else if .Values.externalIndexer.enabled }}
opensearch.hosts: "{{ .Values.externalIndexer.host }}:{{ .Values.externalIndexer.port }}"
{{- else }}
{{- fail "Please enable either .Values.indexer.enabled or .Values.externalIndexer.enabled" }}
{{- end }}

opensearch.ssl.verificationMode: none
opensearch.requestHeadersWhitelist: [ authorization,securitytenant ]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
opensearch_security.auth.unauthenticated_routes: ['/api/stats', '/api/status']
server.ssl.enabled: {{ .Values.dashboard.enable_ssl }}
server.ssl.key: "/usr/share/wazuh-dashboard/certs/key.pem"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/cert.pem"
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home

{{- $authType := list }}
{{- if .Values.dashboard.sso.oidc.enabled }}
{{-   $authType = append $authType "openid" }}
{{- end }}
{{- if .Values.dashboard.sso.saml.enabled }}
{{-   $authType = append $authType "saml" }}
{{- end }}
{{- if .Values.dashboard.basicAuth.enabled }}
{{-   $authType = append $authType "basicauth" }}
{{- end }}
opensearch_security.auth.multiple_auth_enabled: {{ gt ($authType | len) 1 }}
opensearch_security.auth.type: {{ $authType | toJson }}

{{- if .Values.dashboard.sso.oidc.enabled }}
{{- $baseRedirectUrl := .Values.dashboard.sso.oidc.baseRedirectUrl | default .Values.dashboard.ingress.host }}
opensearch_security.openid.connect_url: {{ required "dashboard.sso.oidc.url is required" .Values.dashboard.sso.oidc.url }}
opensearch_security.openid.logout_url: {{ required "dashboard.sso.oidc.logoutUrl is required" .Values.dashboard.sso.oidc.logoutUrl }}
opensearch_security.openid.base_redirect_url: {{ required "dashboard.sso.oidc.baseRedirectUrl is required" $baseRedirectUrl }}
opensearch_security.openid.scope: {{ .Values.dashboard.sso.oidc.scope }}
opensearch_security.openid.client_id: ${OPENSEARCH_OIDC_CLIENT_ID}
opensearch_security.openid.client_secret: ${OPENSEARCH_OIDC_CLIENT_SECRET}

{{- if .Values.dashboard.sso.oidc.customizeLoginButton.enabled }}
opensearch_security.ui.openid.login.buttonname: {{ .Values.dashboard.sso.oidc.customizeLoginButton.text }}
{{- if .Values.dashboard.sso.oidc.customizeLoginButton.showImage }}
opensearch_security.ui.openid.login.brandimage: {{ required "dashboard.sso.oidc.customizeLoginButton.imageUrl is required" .Values.dashboard.sso.oidc.customizeLoginButton.imageUrl }}
opensearch_security.ui.openid.login.showbrandimage: {{ .Values.dashboard.sso.oidc.customizeLoginButton.showImage }}
{{- end }}
{{- end }}
{{- end }}

{{- if .Values.dashboard.sso.saml.enabled }}
server.xsrf.allowlist: ["/_plugins/_security/saml/acs", "/_plugins/_security/saml/logout", "/_opendistro/_security/saml/logout", "/_opendistro/_security/api/authtoken", "/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/acs/idpinitiated", "/_plugins/_security/api/authtoken"]
opensearch_security.session.keepalive: false
{{- end }}

{{- end }}


{{/* Snippet for the configuration file used for defining local decoder */}}
{{- define "wazuh.localDecoder" }}
<!-- Local Decoders -->

<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!--
  - Allowed static fields:
  - location   - where the log came from (only on FTS)
  - srcuser    - extracts the source username
  - dstuser    - extracts the destination (target) username
  - user       - an alias to dstuser (only one of the two can be used)
  - srcip      - source ip
  - dstip      - dst ip
  - srcport    - source port
  - dstport    - destination port
  - protocol   - protocol
  - id         - event id
  - url        - url of the event
  - action     - event action (deny, drop, accept, etc)
  - status     - event status (success, failure, etc)
  - extra_data - Any extra data
-->

<decoder name="local_decoder_example">
    <program_name>local_decoder_example</program_name>
</decoder>
{{- end }}


{{/* Snippet for the configuration file used for defining local rules */}}
{{- define "wazuh.localRules" }}
<!--
  Enhanced AlienVault OTX Threat Intelligence Rules for Wazuh
  Rules for detecting threats from OTX feeds with SSH integration
-->

<group name="otx_threat_intelligence">

  <!-- OTX Malware Hash Detection Rules -->
  <rule id="110010" level="14">
    <if_sid>554, 550</if_sid>
    <list field="md5" lookup="match_key">etc/otx/otx-malware-hashes</list>
    <description>OTX: Malware file detected (MD5): $(file) - Hash: $(md5) - Threat: $list</description>
    <mitre>
      <id>T1204.002</id>
    </mitre>
    <group>otx,malware,file_integrity,</group>
  </rule>

  <rule id="110011" level="14">
    <if_sid>554, 550</if_sid>
    <list field="sha1" lookup="match_key">etc/otx/otx-malware-hashes</list>
    <description>OTX: Malware file detected (SHA1): $(file) - Hash: $(sha1) - Threat: $list</description>
    <mitre>
      <id>T1204.002</id>
    </mitre>
    <group>otx,malware,file_integrity,</group>
  </rule>

  <rule id="110012" level="14">
    <if_sid>554, 550</if_sid>
    <list field="sha256" lookup="match_key">etc/otx/otx-malware-hashes</list>
    <description>OTX: Malware file detected (SHA256): $(file) - Hash: $(sha256) - Threat: $list</description>
    <mitre>
      <id>T1204.002</id>
    </mitre>
    <group>otx,malware,file_integrity,</group>
  </rule>

  <!-- Enhanced OTX Malicious IP Detection Rules with SSH Integration -->
  <rule id="110013" level="13">
    <if_sid>1002, 5700, 5701, 5706, 5710, 5716, 5720, 5731, 5760, 5763, 5712</if_sid>
    <list field="srcip" lookup="match_key">etc/otx/otx-malicious-ips</list>
    <description>OTX: Connection from malicious IP: $(srcip) - Threat: $list</description>
    <mitre>
      <id>T1071</id>
      <id>T1110</id>
    </mitre>
    <group>otx,network,malicious_ip,ssh_threat,</group>
  </rule>

  <rule id="110014" level="13">
    <if_sid>1002, 5700</if_sid>
    <list field="dstip" lookup="match_key">etc/otx/otx-malicious-ips</list>
    <description>OTX: Connection to malicious IP: $(dstip) - Threat: $list</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>otx,network,malicious_ip,</group>
  </rule>

  <!-- SSH-Specific Malicious IP Rules -->
  <rule id="110020" level="15">
    <if_sid>5712, 5720, 5763</if_sid>
    <list field="srcip" lookup="match_key">etc/otx/otx-malicious-ips</list>
    <description>OTX: SSH brute force attack from known malicious IP: $(srcip) - Threat: $list</description>
    <mitre>
      <id>T1110</id>
      <id>T1021.004</id>
    </mitre>
    <group>otx,ssh,brute_force,malicious_ip,</group>
  </rule>

  <rule id="110021" level="14">
    <if_sid>5701, 5706, 5731</if_sid>
    <list field="srcip" lookup="match_key">etc/otx/otx-malicious-ips</list>
    <description>OTX: SSH reconnaissance/scan from known malicious IP: $(srcip) - Threat: $list</description>
    <mitre>
      <id>T1046</id>
      <id>T1190</id>
    </mitre>
    <group>otx,ssh,reconnaissance,malicious_ip,</group>
  </rule>

  <rule id="110022" level="16">
    <if_sid>5707, 5714</if_sid>
    <list field="srcip" lookup="match_key">etc/otx/otx-malicious-ips</list>
    <description>OTX: SSH exploit attempt from known malicious IP: $(srcip) - Threat: $list</description>
    <mitre>
      <id>T1210</id>
      <id>T1068</id>
    </mitre>
    <group>otx,ssh,exploit,malicious_ip,</group>
  </rule>

  <rule id="110023" level="12">
    <if_sid>5715</if_sid>
    <list field="srcip" lookup="match_key">etc/otx/otx-malicious-ips</list>
    <description>OTX: Successful SSH authentication from known malicious IP: $(srcip) - Threat: $list</description>
    <mitre>
      <id>T1078</id>
      <id>T1021.004</id>
    </mitre>
    <group>otx,ssh,authentication_success,malicious_ip,</group>
  </rule>

  <!-- Domain-based Detection -->
  <rule id="110015" level="12">
    <if_sid>1002</if_sid>
    <list field="dstip" lookup="address_match_key">etc/otx/otx-malicious-domains</list>
    <description>OTX: Connection to malicious domain/IP: $(dstip) - Threat: $list</description>
    <mitre>
      <id>T1071.004</id>
    </mitre>
    <group>otx,dns,malicious_domain,</group>
  </rule>

  <rule id="110016" level="12">
    <list field="hostname" lookup="match_key">etc/otx/otx-malicious-domains</list>
    <description>OTX: Hostname matches malicious domain: $(hostname) - Threat: $list</description>
    <mitre>
      <id>T1071.004</id>
    </mitre>
    <group>otx,network,malicious_domain,</group>
  </rule>

  <!-- Web Access to Malicious Domains -->
  <rule id="110017" level="11">
    <if_sid>31100, 31101, 31102, 31103, 31104</if_sid>
    <list field="url" lookup="match_key">etc/otx/otx-malicious-domains</list>
    <description>OTX: Web access to malicious domain: $(url) - Threat: $list</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
    <group>otx,web,malicious_domain,</group>
  </rule>

  <!-- Failed Login Attempts from Malicious IPs -->
  <rule id="110024" level="13">
    <if_sid>5710, 5716, 5718, 5760</if_sid>
    <list field="srcip" lookup="match_key">etc/otx/otx-malicious-ips</list>
    <description>OTX: Failed SSH authentication from known malicious IP: $(srcip) - Threat: $list</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1021.004</id>
    </mitre>
    <group>otx,ssh,authentication_failed,malicious_ip,</group>
  </rule>

  <!-- SSH Connection Anomalies from Malicious IPs -->
  <rule id="110025" level="11">
    <if_sid>5704, 5705, 5740, 5741, 5742</if_sid>
    <list field="srcip" lookup="match_key">etc/otx/otx-malicious-ips</list>
    <description>OTX: SSH connection anomaly from known malicious IP: $(srcip) - Threat: $list</description>
    <mitre>
      <id>T1021.004</id>
    </mitre>
    <group>otx,ssh,connection_anomaly,malicious_ip,</group>
  </rule>

  <!-- SSH Protocol Violations from Malicious IPs -->
  <rule id="110026" level="12">
    <if_sid>5747, 5748, 5749, 5750, 5752, 5753</if_sid>
    <list field="srcip" lookup="match_key">etc/otx/otx-malicious-ips</list>
    <description>OTX: SSH protocol violation from known malicious IP: $(srcip) - Threat: $list</description>
    <mitre>
      <id>T1021.004</id>
    </mitre>
    <group>otx,ssh,protocol_violation,malicious_ip,</group>
  </rule>

  <!-- Correlation Rules for Multiple SSH Events from Same Malicious IP -->
  <rule id="110027" level="14" frequency="3" timeframe="300">
    <if_matched_sid>110020, 110021, 110024, 110025</if_matched_sid>
    <same_source_ip/>
    <description>OTX: Multiple SSH threats detected from same malicious IP: $(srcip)</description>
    <mitre>
      <id>T1110</id>
      <id>T1021.004</id>
    </mitre>
    <group>otx,ssh,correlation,malicious_ip,</group>
  </rule>

  <!-- OTX Integration Status Rules -->
  <rule id="110018" level="3">
    <if_sid>530</if_sid>
    <match>otx-threat-intel-update</match>
    <description>OTX threat intelligence feeds updated successfully</description>
    <group>otx,integration,</group>
  </rule>

  <rule id="110019" level="5">
    <if_sid>530</if_sid>
    <match>otx-threat-intel-update</match>
    <match>Error|Failed|Exception</match>
    <description>OTX threat intelligence feed update failed</description>
    <group>otx,integration,errors,</group>
  </rule>

  <!-- Generic Network Rules for OTX Enhancement -->
  <rule id="110028" level="10">
    <if_sid>5712, 1001, 1002, 1003</if_sid>
    <list field="srcip" lookup="match_key">etc/otx/otx-malicious-ips</list>
    <description>OTX: Network activity from known malicious IP: $(srcip) - Threat: $list</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>otx,network,malicious_ip,</group>
  </rule>

  <!-- User Authentication Correlation -->
  <rule id="110029" level="13">
    <if_sid>5501, 5502, 5503</if_sid>
    <list field="srcip" lookup="match_key">etc/otx/otx-malicious-ips</list>
    <description>OTX: User authentication event from known malicious IP: $(srcip) - Threat: $list</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>otx,authentication,malicious_ip,</group>
  </rule>

  <!-- Silence repeating kubelet restart failures -->
  <rule id="100005" level="0">
    <if_sid>40704</if_sid>
    <description>Ignore repeating Kubelet restart failures to save disk space.</description>
  </rule>

  <!-- Silence repeating promtail SELinux denials -->
  <rule id="100006" level="0">
    <if_sid>80730</if_sid>
    <description>Ignore Promtail SELinux denials until SELinux is fixed.</description>
  </rule>

  <!-- Silence repeating node_exporter SELinux denials -->
  <rule id="100007" level="0">
    <if_sid>80730</if_sid>
    <match>node_exporter</match>
    <description>Ignore node_exporter SELinux denials to reduce noise.</description>
  </rule>

  <!-- Silence repetitive iSCSI reconnect noise -->
  <rule id="100008" level="0">
    <program_name>iscsid</program_name>
    <match>cannot make a connection</match>
    <description>Ignore repetitive iSCSI connection retry noise.</description>
  </rule>

  <rule id="100009" level="0">
    <program_name>iscsid</program_name>
    <match>connect to</match>
    <description>Ignore repetitive iSCSI connection refused noise.</description>
  </rule>

</group>
{{- end }}


{{/* Snippet for the internal options configuration */}}
{{- define "wazuh.internalOptions" }}
# internal_options.conf, Daniel B. Cid (dcid @ ossec.net).
#
# DO NOT TOUCH THIS FILE. The default configuration
# is at ossec.conf. More information at:
# https://documentation.wazuh.com
#
# This file should be handled with care. It contain
# run time modifications that can affect the use
# of ossec. Only change it if you know what you
# are doing. Again, look first at ossec.conf
# for most of the things you want to change.


# Analysisd default rule timeframe.
analysisd.default_timeframe=360
# Analysisd stats maximum diff.
analysisd.stats_maxdiff=999000
# Analysisd stats minimum diff.
analysisd.stats_mindiff=1250
# Analysisd stats percentage (how much to differ from average)
analysisd.stats_percent_diff=150
# Analysisd FTS list size.
analysisd.fts_list_size=32
# Analysisd FTS minimum string size.
analysisd.fts_min_size_for_str=14
# Analysisd Enable the firewall log (at logs/firewall/firewall.log)
# 1 to enable, 0 to disable.
analysisd.log_fw=1
# Maximum number of fields in a decoder (order tag) [32..1024]
analysisd.decoder_order_size=256
# Output GeoIP data at JSON alerts
analysisd.geoip_jsonout=0
# Maximum label cache age (margin seconds with no reloading) [0..60]
analysisd.label_cache_maxage=10
# Show hidden labels on alerts
analysisd.show_hidden_labels=0
# Maximum number of file descriptor that Analysisd can open [1024..1048576]
analysisd.rlimit_nofile=458752
# Minimum output rotate interval. This limits rotation by time and size. [10..86400]
analysisd.min_rotate_interval=600
# Number of event decoder threads
analysisd.event_threads=0
# Number of syscheck decoder threads
analysisd.syscheck_threads=0
# Number of syscollector decoder threads
analysisd.syscollector_threads=0
# Number of rootcheck decoder threads
analysisd.rootcheck_threads=0
# Number of security configuration assessment decoder threads
analysisd.sca_threads=0
# Number of hostinfo decoder threads
analysisd.hostinfo_threads=0
# Number of Windows event decoder threads
analysisd.winevt_threads=0
# Number of rule matching threads
analysisd.rule_matching_threads=0
# Number of database synchronization dispatcher threads [0..32]
analysisd.dbsync_threads=0
# Decoder event queue size
analysisd.decode_event_queue_size=16384
# Decode syscheck queue size
analysisd.decode_syscheck_queue_size=16384
# Decode syscollector queue size
analysisd.decode_syscollector_queue_size=16384
# Decode rootcheck queue size
analysisd.decode_rootcheck_queue_size=16384
# Decode security configuration assessment queue size
analysisd.decode_sca_queue_size=16384
# Decode hostinfo queue size
analysisd.decode_hostinfo_queue_size=16384
# Decode winevt queue size
analysisd.decode_winevt_queue_size=16384
# Decode Output queue
analysisd.decode_output_queue_size=16384
# Archives log queue size
analysisd.archives_queue_size=16384
# Statistical log queue size
analysisd.statistical_queue_size=16384
# Alerts log queue size
analysisd.alerts_queue_size=16384
# Firewall log queue size
analysisd.firewall_queue_size=16384
# FTS log queue size
analysisd.fts_queue_size=16384
# Database synchronization message queue size [0..2000000]
analysisd.dbsync_queue_size=16384
# Upgrade message queue size
analysisd.upgrade_queue_size=16384
# Interval for analysisd status file updating (seconds) [0..86400]
# 0 means disabled
analysisd.state_interval=5


# Logcollector file loop timeout (check every 2 seconds for file changes)
logcollector.loop_timeout=2

# Logcollector number of attempts to open a log file [2..998] (0=infinite)
logcollector.open_attempts=0

# Logcollector - If it should accept remote commands from the manager
logcollector.remote_commands=0

# Logcollector - File checking interval (seconds) [0..1024]
logcollector.vcheck_files=64

# Logcollector - Maximum number of lines to read from the same file [100..1000000]
# 0. Disable line burst limitation
logcollector.max_lines=10000

# Logcollector - Maximum number of files to be monitored [1..100000]
logcollector.max_files=1000

# Time to reattempt a socket connection after a failure [1..3600]
logcollector.sock_fail_time=300

# Logcollector - Number of input threads for reading files
logcollector.input_threads=4

# Logcollector - Output queue size [128..220000]
logcollector.queue_size=1024

# Sample log length limit for errors about large message [1..4096]
logcollector.sample_log_length=64

# Maximum number of file descriptor that Logcollector can open [1024..1048576]
# This value must be higher than logcollector.max_files
logcollector.rlimit_nofile=1100

# Force file handler reloading: close and reopen monitored files
# 0: Disabled
# 1: Enabled
logcollector.force_reload=0

# File reloading interval, in seconds, if force_reload=1 [1..86400]
# This interval must be greater or equal than vcheck_files.
logcollector.reload_interval=64

# File reloading delay (between close and open), in milliseconds [0..30000]
logcollector.reload_delay=1000

# Excluded files refresh interval, in seconds [1..172800]
logcollector.exclude_files_interval=86400

# State generation updating interval, in seconds [0..3600]
# 0 means state file creation and updating is disabled
logcollector.state_interval=60

# Logbuilder IP update interval [0..3600]
logcollector.ip_update_interval=60

# Remoted counter io flush.
remoted.recv_counter_flush=128

# Remoted compression averages printout.
remoted.comp_average_printout=19999

# Verify msg id (set to 0 to disable it)
remoted.verify_msg_id=0

# Don't exit when client.keys empty
remoted.pass_empty_keyfile=1

# Number of shared file sender threads
remoted.sender_pool=8

# Limit of parallel request dispatchers [1..4096]
remoted.request_pool=1024

# Timeout to reject a new request (seconds) [1..600]
remoted.request_timeout=10

# Timeout for request responses (seconds) [1..3600]
remoted.response_timeout=60

# Retransmission timeout seconds [0..60]
remoted.request_rto_sec=1

# Retransmission timeout milliseconds [0..999]
remoted.request_rto_msec=0

# Max. number of sending attempts [1..16]
remoted.max_attempts=4

# Shared files reloading interval (sec) [1..18000]
remoted.shared_reload=10

# Maximum number of file descriptor that Remoted can open [1024..1048576]
remoted.rlimit_nofile=458752

# Maximum time waiting for a client response in TCP (seconds) [1..60]
remoted.recv_timeout=1

# Merge shared configuration to be broadcasted to agents
# 0. Disable
# 1. Enable (default)
remoted.merge_shared=1

# Store the temporary shared configuration file on disk
# 0. No, store in memory (default)
# 1. Yes, store on disk
remoted.disk_storage=0

# Keys file reloading latency (seconds) [1..3600]
remoted.keyupdate_interval=10

# Number of parallel worker threads [1..16]
remoted.worker_pool=4

# Interval for remoted status file updating (seconds) [0..86400]
# 0 means disabled
remoted.state_interval=5

# Guess the group to which the agent belongs
# 0. No, do not guess (default)
# 1. Yes, do guess
remoted.guess_agent_group=0

# Receiving chunk size for TCP. We suggest using powers of two. [1024..16384]
remoted.receive_chunk=4096

# Sending chunk size for TCP. We suggest using powers of two. [512..16384]
remoted.send_chunk=4096

# Send buffer size for queue messages to send. We suggest using powers of two. [65536..1048576]
remoted.send_buffer_size=131072

# Sleep time to retry delivery to a client in TCP (seconds) [1..60]
remoted.send_timeout_to_retry=1

# Deallocate network buffers after usage.
# 0. Do not deallocate memory.
# 1. Shrink memory to the reception chunk.
# 2. Full memory deallocation.
remoted.buffer_relax=1

# Keepalive options
# Time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes [1..7200]
remoted.tcp_keepidle=30
# The time (in seconds) between individual keepalive probes [1..100]
remoted.tcp_keepintvl=10
# Maximum number of keepalive probes TCP should send before dropping the connection [1..50]
remoted.tcp_keepcnt=3

# Timeout to execute remote requests [1..3600]
execd.request_timeout=60

# Max timeout to lock the restart [0..3600]
execd.max_restart_lock=600

# Maild strict checking (0=disabled, 1=enabled)
maild.strict_checking=1

# Maild grouping (0=disabled, 1=enabled)
# Groups alerts within the same e-mail.
maild.grouping=1

# Maild full subject (0=disabled, 1=enabled)
maild.full_subject=0

# Maild display GeoIP data (0=disabled, 1=enabled)
maild.geoip=1


# Monitord day_wait. Amount of seconds to wait before rotating/compressing/signing [0..600]
# the files.
monitord.day_wait=10

# Monitord compress. (0=do not compress, 1=compress)
monitord.compress=1

# Monitord sign. (0=do not sign, 1=sign)
monitord.sign=1

# Monitord monitor_agents. (0=do not monitor, 1=monitor)
monitord.monitor_agents=1

# Rotate plain and JSON logs daily. (0=no, 1=yes)
monitord.rotate_log=1

# Days to keep old ossec.log files [0..500]
monitord.keep_log_days=31

# Size of internal log files to rotate them (Megabytes) [0..4096]
monitord.size_rotate=512

# Maximum number of rotations per day for internal logs [1..256]
monitord.daily_rotations=12

# Number of minutes for deleting a disconnected agent [0..9600]. (0=disabled)
monitord.delete_old_agents=0

# Syscheck perform a delay when dispatching real-time notifications so it avoids
# triggering on some temporary files like vim edits. (ms) [0..1000]
syscheck.rt_delay=5

# Maximum number of directories monitored for realtime on windows [1..1024]
syscheck.max_fd_win_rt=256

# Maximum number of directories monitored for who-data on Linux [1..4096]
syscheck.max_audit_entries=256

# Maximum level of recursivity allowed [1..320]
syscheck.default_max_depth=256

# Check interval of the symbolic links configured in the directories section [1..2592000]
syscheck.symlink_scan_interval=600

# Maximum file size for calcuting integrity hashes in MBytes [0..4095]
# A value of 0 MB means to disable this filter
syscheck.file_max_size=1024

# Rootcheck checking/usage speed. The default is to sleep 50 milliseconds
# per each PID or suspictious port.
rootcheck.sleep=50

# Time since the agent buffer is full to consider events flooding
agent.tolerance=15
# Level of occupied capacity in Agent buffer to trigger a warning message
agent.warn_level=90
# Level of occupied capacity in Agent buffer to come back to normal state
agent.normal_level=70
# Minimum events per second, configurable at XML settings [1..1000]
agent.min_eps=50
# Interval for agent status file updating (seconds) [0..86400]
# 0 means disabled
agent.state_interval=5

# Maximum time waiting for a server response in TCP (seconds) [1..600]
agent.recv_timeout=60

# Apply remote configuration
# 0. Disabled
# 1. Enabled
agent.remote_conf=1

# Database - maximum number of reconnect attempts
dbd.reconnect_attempts=10

# Wazuh modules - nice value for tasks. Lower value means higher priority
wazuh_modules.task_nice=10

# Wazuh modules - maximum number of events per second sent by each module [1..1000]
wazuh_modules.max_eps=100

# Wazuh modules - time for a process to quit before killing it [0..3600]
# 0: Kill immediately
wazuh_modules.kill_timeout=10

# Wazuh database module settings

# Synchronize agent database with client.keys
wazuh_database.sync_agents=1

# Sync data in real time (supported on Linux only)
# 0. Disabled
# 1. Enabled (default)
wazuh_database.real_time=1

# Time interval between cycles (used only if real time disabled)
# Default: 60 seconds (1 minute). Max: 86400 seconds (1 day)
wazuh_database.interval=60

# Maximum queued events (for inotify)
# 0. Use system default
wazuh_database.max_queued_events=0

# Enable download module
# 0. Disabled
# 1. Enabled (default)
wazuh_download.enabled=1

# Number of worker threads (1..32)
wazuh_db.worker_pool_size=8

# Minimum time margin before committing (1..3600)
wazuh_db.commit_time_min=10

# Maximum time margin before committing (1..3600)
wazuh_db.commit_time_max=60

# Number of allowed open databases before closing (1..4096)
wazuh_db.open_db_limit=64

# Maximum number of file descriptor that WazuhDB can open [1024..1048576]
wazuh_db.rlimit_nofile=458752

# Indicates the max fragmentation allowed.
# [0..100]
wazuh_db.max_fragmentation=90

# Indicates the allowed fragmentation threshold.
# [0..100]
wazuh_db.fragmentation_threshold=75

# Indicates the allowed fragmentation difference between the last time the vacuum was performed and the current measurement.
# [0..100]
wazuh_db.fragmentation_delta=5

# Indicates the minimum percentage of free pages present in a database that can trigger a vacuum. [0..99]
wazuh_db.free_pages_percentage=0

# Interval for database fragmentation check, in seconds [1..30758400]
wazuh_db.check_fragmentation_interval=7200

# Wazuh Command Module - If it should accept remote commands from the manager
wazuh_command.remote_commands=0

# Wazuh default stack size for child threads in KiB (2048..65536)
wazuh.thread_stack_size=8192

# Security Configuration Assessment DB request interval in minutes [0..60]
# This option sets the maximum waiting time to resend a scan when the DB integrity check fails
sca.request_db_interval=5

# Enable it to accept execute commands from SCA policies pushed from the manager in the shared configuration
# Local policies ignore this option
sca.remote_commands=0

# Default timeout for executed commands during a SCA scan in seconds [1..300]
sca.commands_timeout=30

# Network timeout for Authd clients
auth.timeout_seconds=1
auth.timeout_microseconds=0

# Vulnerability detector LRUs size
vulnerability-detection.translation_lru_size=2048
vulnerability-detection.osdata_lru_size=1000
vulnerability-detection.remediation_lru_size=2048

# Vulnerability detector - Enable or disable the scan manager
# 0. Enabled
# 1. Disabled
vulnerability-detection.disable_scan_manager=1

# Debug options.
# Debug 0 -> no debug
# Debug 1 -> first level of debug
# Debug 2 -> full debugging

# Windows debug (used by the Windows agent)
windows.debug=0

# Syscheck (local, server and Unix agent)
syscheck.debug=0

# Remoted (server debug)
remoted.debug=0

# Analysisd (server or local)
analysisd.debug=0

# Auth daemon debug (server)
authd.debug=0

# Exec daemon debug (server, local or Unix agent)
execd.debug=0

# Monitor daemon debug (server, local or Unix agent)
monitord.debug=0

# Log collector (server, local or Unix agent)
logcollector.debug=0

# Integrator daemon debug (server, local or Unix agent)
integrator.debug=0

# Unix agentd
agent.debug=0

# Wazuh DB debug level
wazuh_db.debug=0

wazuh_modules.debug=0

# Wazuh Cluster debug level
wazuh_clusterd.debug=0
# EOF

{{- end }}

{{/* Snippet for the configuration file used by wazuh master */}}
{{- define "wazuh.master.conf" }}
<!--
  Wazuh - Manager - Default configuration for ubuntu 16.04
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh

  Customization: TCP on port 1514
  Customization: Cluster mode enabled, master node
-->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>ossecm@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <queue_size>131072</queue_size>
    <agents_disconnection_time>20s</agents_disconnection_time>
    <agents_disconnection_alert_time>100s</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
  <logging>
    <log_format>plain</log_format>
  </logging>

{{- range .Values.wazuh.worker.service.ports }}
  {{- if eq .name "agents-events" }}
    <remote>
      <connection>secure</connection>
      <port>{{ .port }}</port>
      <protocol>tcp</protocol>
      <queue_size>131072</queue_size>
    </remote>
  {{- end }}
{{- end }}

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_unixaudit>yes</check_unixaudit>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>

    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>

    <system_audit>/var/ossec/etc/rootcheck/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/rootcheck/system_audit_ssh.txt</system_audit>

    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="open-scap">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
  </wodle>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <!-- Osquery integration -->
  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <!-- System inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>12h</feed-update-interval>
  </vulnerability-detection>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
    {{- if .Values.indexer.enabled }}
      <host>https://{{ include "wazuh.indexer.fullname" . }}-indexer:{{ .Values.indexer.service.httpPort }}</host>
    {{- end }}
    {{- if .Values.externalIndexer.enabled }}
      <host>https://{{ .Values.externalIndexer.host }}:{{ .Values.externalIndexer.port }}</host>
    {{- end }}
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/ssl/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/ssl/filebeat.pem</certificate>
      <key>/etc/ssl/filebeat.key</key>
    </ssl>
  </indexer>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Generate alert when new file detected -->
    <alert_new_files>yes</alert_new_files>

    <!-- Don't ignore files that change more than 'frequency' times -->
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>

    <!-- Remove not monitored files -->
    <remove_old_diff>yes</remove_old_diff>

    <!-- Allow the system to restart Auditd after installing the plugin -->
    <restart_audit>yes</restart_audit>
  </syscheck>

  <!-- Active response -->
  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.66.0.2</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account.sh</executable>
    <expect>user</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-ossec</name>
    <executable>restart-ossec.sh</executable>
    <expect></expect>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null-2012</name>
    <executable>route-null-2012.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh</name>
    <executable>netsh.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh-win-2016</name>
    <executable>netsh-win-2016.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Active Response configurations - Place AFTER command definitions -->
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712,5703,5705</rules_id>
    <timeout>120</timeout>
  </active-response>

  <!-- Log analysis -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-sources</list>
    <list>etc/lists/amazon/aws-eventnames</list>

    <!-- OTX Threat Intelligence Lists -->
    <list>etc/otx/otx-malware-hashes</list>
    <list>etc/otx/otx-malicious-ips</list>
    <list>etc/otx/otx-malicious-domains</list>

    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <rule_test>
      <enabled>yes</enabled>
      <threads>1</threads>
      <max_sessions>64</max_sessions>
      <session_timeout>15m</session_timeout>
  </rule_test>

  <!-- Configuration for ossec-authd
    To enable this service, run:
    wazuh-control enable auth
  -->
  <auth>
    <disabled>no</disabled>
{{- range .Values.wazuh.master.service.ports }}
  {{- if eq .name "registration" }}
    <port>{{ .port }}</port>
  {{- end }}
{{- end }}
    <use_source_ip>no</use_source_ip>
    <force>
      <enabled>yes</enabled>
      <key_mismatch>yes</key_mismatch>
      <disconnected_time enabled="yes">1h</disconnected_time>
      <after_registration_time>1h</after_registration_time>
    </force>
    <purge>no</purge>
    <use_password>yes</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>{{ include "wazuh.fullname" . }}-manager-master-0</node_name>
    <node_type>master</node_type>
    <key>{{ .Values.wazuh.key }}</key>
    <port>{{ .Values.wazuh.service.port }}</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>{{ include "wazuh.fullname" . }}-manager-master-0.{{ include "wazuh.fullname" . }}-manager-cluster</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  {{- if .Values.wazuh.master.extraConf }}
  {{ .Values.wazuh.master.extraConf | indent 2 }}
  {{- end }}
</ossec_config>
{{- end }}

{{/* Snippet for the configuration file used by wazuh worker */}}
{{- define "wazuh.worker.conf" }}
<!--
  Wazuh - Manager - Default configuration for ubuntu 16.04
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh

  Customization: TCP on port 1514
  Customization: Cluster mode enabled, worker node
-->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>ossecm@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <queue_size>131072</queue_size>
    <agents_disconnection_time>20s</agents_disconnection_time>
    <agents_disconnection_alert_time>100s</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
  <logging>
    <log_format>plain</log_format>
  </logging>

{{- range .Values.wazuh.worker.service.ports }}
  {{- if eq .name "agents-events" }}
    <remote>
      <connection>secure</connection>
      <port>{{ .port }}</port>
      <protocol>tcp</protocol>
      <queue_size>131072</queue_size>
    </remote>
  {{- end }}
{{- end }}

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_unixaudit>yes</check_unixaudit>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>

    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>

    <system_audit>/var/ossec/etc/rootcheck/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/rootcheck/system_audit_ssh.txt</system_audit>

    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="open-scap">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
  </wodle>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <!-- Osquery integration -->
  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <!-- System inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>12h</feed-update-interval>
  </vulnerability-detection>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
    {{- if .Values.indexer.enabled }}
      <host>https://{{ include "wazuh.indexer.fullname" . }}-indexer:{{ .Values.indexer.service.httpPort }}</host>
    {{- end }}
    {{- if .Values.externalIndexer.enabled }}
      <host>https://{{ .Values.externalIndexer.host }}:{{ .Values.externalIndexer.port }}</host>
    {{- end }}
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/ssl/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/ssl/filebeat.pem</certificate>
      <key>/etc/ssl/filebeat.key</key>
    </ssl>
  </indexer>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Generate alert when new file detected -->
    <alert_new_files>yes</alert_new_files>

    <!-- Don't ignore files that change more than 'frequency' times -->
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>

    <!-- Remove not monitored files -->
    <remove_old_diff>yes</remove_old_diff>

    <!-- Allow the system to restart Auditd after installing the plugin -->
    <restart_audit>yes</restart_audit>
  </syscheck>

  <!-- Active response -->
  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.66.0.2</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account.sh</executable>
    <expect>user</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-ossec</name>
    <executable>restart-ossec.sh</executable>
    <expect></expect>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null-2012</name>
    <executable>route-null-2012.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh</name>
    <executable>netsh.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh-win-2016</name>
    <executable>netsh-win-2016.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Active Response configurations - Place AFTER command definitions -->
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712,5703,5705</rules_id>
    <timeout>120</timeout>
  </active-response>

  <!-- Log analysis -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-sources</list>
    <list>etc/lists/amazon/aws-eventnames</list>

    <!-- OTX Threat Intelligence Lists -->
    <list>etc/otx/otx-malware-hashes</list>
    <list>etc/otx/otx-malicious-ips</list>
    <list>etc/otx/otx-malicious-domains</list>

    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <rule_test>
    <enabled>yes</enabled>
    <threads>1</threads>
    <max_sessions>64</max_sessions>
    <session_timeout>15m</session_timeout>
  </rule_test>

  <!-- Configuration for ossec-authd
    To enable this service, run:
    wazuh-control enable auth
  -->
  <auth>
    <disabled>no</disabled>
{{- range .Values.wazuh.master.service.ports }}
  {{- if eq .name "registration" }}
    <port>{{ .port }}</port>
  {{- end }}
{{- end }}
    <use_source_ip>no</use_source_ip>
    <force>
      <enabled>yes</enabled>
      <key_mismatch>yes</key_mismatch>
      <disconnected_time enabled="yes">1h</disconnected_time>
      <after_registration_time>1h</after_registration_time>
    </force>
    <purge>no</purge>
    <use_password>yes</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>{{ include "wazuh.fullname" . }}-manager-worker-___INDEX___</node_name>
    <node_type>worker</node_type>
    <key>{{ .Values.wazuh.key }}</key>
    <port>{{ .Values.wazuh.service.port }}</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <!-- Kubernetes Service Pointing to Master node -->
        <node>{{ include "wazuh.fullname" . }}-manager-master-0.{{ include "wazuh.fullname" . }}-manager-cluster</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

{{- if .Values.wazuh.syslog_enable }}
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>tcp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
    <local_ip>0.0.0.0</local_ip>
  </remote>
{{- end }}

  {{- if .Values.wazuh.worker.extraConf }}
  {{ .Values.wazuh.worker.extraConf | indent 2 }}
  {{- end }}
</ossec_config>
{{- end }}


{{- define "wazuh.otxThreatFeeds" }}
#!/usr/bin/env python3
"""
AlienVault OTX Threat Intelligence Feed Updater for Wazuh
Fetches IoCs from OTX and creates Wazuh CDB lists
"""

import sys
import os
import json
import time
import logging
from datetime import datetime, timedelta

try:
    from OTXv2 import OTXv2
    import requests
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Please install: pip3 install OTXv2 requests")
    sys.exit(1)

# Configuration
OTX_API_KEY = os.environ.get('OTX_API_KEY', '')
LISTS_DIR = '/var/ossec/etc/otx'
LOG_FILE = '/var/ossec/logs/otx_integration.log'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def setup_otx_client():
    """Initialize OTX client"""
    if not OTX_API_KEY:
        logging.error("OTX_API_KEY environment variable not set")
        return None
    
    try:
        otx = OTXv2(OTX_API_KEY)
        logging.info("OTX client initialized successfully")
        return otx
    except Exception as e:
        logging.error(f"Failed to initialize OTX client: {e}")
        return None


def fetch_malware_hashes(otx, days_back=1, max_results=1000):
    """Fetch malware file hashes from OTX"""
    logging.info(f"Fetching malware hashes from last {days_back} days...")
    hashes = []
    
    try:
        # Use getsince with limit for better performance
        since_date = (datetime.now() - timedelta(days=days_back)).isoformat()
        pulses = otx.getsince(since_date, limit=50)  # Limit to 50 recent pulses
        
        count = 0
        for pulse in pulses:
            if count >= max_results:
                break
                
            for indicator in pulse.get('indicators', []):
                if count >= max_results:
                    break
                    
                if indicator.get('type') in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
                    hash_value = indicator.get('indicator', '').lower()
                    pulse_name = pulse.get('name', 'unknown')
                    
                    if hash_value and len(hash_value) >= 32:
                        hashes.append(f"{hash_value}:otx_{pulse_name.replace(' ', '_').replace(',', '_')}")
                        count += 1
        
        logging.info(f"Fetched {len(hashes)} malware hashes")
        return hashes
        
    except Exception as e:
        logging.error(f"Error fetching malware hashes: {e}")
        return []

def fetch_malicious_ips(otx, days_back=1, max_results=1000):
    """Fetch malicious IP addresses from OTX"""
    logging.info(f"Fetching malicious IPs from last {days_back} days...")
    ips = []
    
    try:
        since_date = (datetime.now() - timedelta(days=days_back)).isoformat()
        pulses = otx.getsince(since_date, limit=50)  # Limit to 50 recent pulses
        
        count = 0
        for pulse in pulses:
            if count >= max_results:
                break
                
            for indicator in pulse.get('indicators', []):
                if count >= max_results:
                    break
                    
                if indicator.get('type') == 'IPv4':
                    ip = indicator.get('indicator', '')
                    pulse_name = pulse.get('name', 'unknown')
                    
                    if ip and not ip.startswith(('10.', '192.168.', '172.16.')):
                        ips.append(f"{ip}:otx_{pulse_name.replace(' ', '_').replace(',', '_')}")
                        count += 1
        
        logging.info(f"Fetched {len(ips)} malicious IPs")
        return ips
        
    except Exception as e:
        logging.error(f"Error fetching malicious IPs: {e}")
        return []

def fetch_malicious_domains(otx, days_back=1, max_results=1000):
    """Fetch malicious domains from OTX"""
    logging.info(f"Fetching malicious domains from last {days_back} days...")
    domains = []
    
    try:
        since_date = (datetime.now() - timedelta(days=days_back)).isoformat()
        pulses = otx.getsince(since_date, limit=50)  # Limit to 50 recent pulses
        
        count = 0
        for pulse in pulses:
            if count >= max_results:
                break
                
            for indicator in pulse.get('indicators', []):
                if count >= max_results:
                    break
                    
                if indicator.get('type') in ['domain', 'hostname']:
                    domain = indicator.get('indicator', '')
                    pulse_name = pulse.get('name', 'unknown')
                    
                    if domain and '.' in domain:
                        domains.append(f"{domain}:otx_{pulse_name.replace(' ', '_').replace(',', '_')}")
                        count += 1
        
        logging.info(f"Fetched {len(domains)} malicious domains")
        return domains
        
    except Exception as e:
        logging.error(f"Error fetching malicious domains: {e}")
        return []



def write_cdb_list(filename, data, header_comment):
    """Write data to CDB list file"""
    filepath = os.path.join(LISTS_DIR, filename)
    
    try:
        with open(filepath, 'w') as f:
            f.write(f"# {header_comment}\n")
            f.write(f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total entries: {len(data)}\n\n")
            
            for entry in data:
                f.write(f"{entry}\n")
        
        # Set proper permissions for Wazuh
        import pwd, grp
        try:
            ossec_uid = pwd.getpwnam('wazuh').pw_uid
            ossec_gid = grp.getgrnam('wazuh').gr_gid
            os.chown(filepath, ossec_uid, ossec_gid)
        except (KeyError, OSError):
            # Fallback: try common Wazuh user IDs or leave as root readable
            os.chmod(filepath, 0o644)  # Make readable by all
            logging.warning(f"Could not set ossec ownership for {filename}, set to world-readable")
            return
            
        os.chmod(filepath, 0o640)
        logging.info(f"Successfully wrote {len(data)} entries to {filename}")
        
    except Exception as e:
        logging.error(f"Error writing to {filename}: {e}")


def main():
    """Main function"""
    logging.info("Starting OTX threat intelligence update...")
    
    # Setup OTX client
    otx = setup_otx_client()
    if not otx:
        sys.exit(1)
    
    # Create lists directory if it doesn't exist
    os.makedirs(LISTS_DIR, exist_ok=True)
    
    # Fetch and write malware hashes
    malware_hashes = fetch_malware_hashes(otx, days_back=60)
    if malware_hashes:
        write_cdb_list('otx-malware-hashes', malware_hashes, 
                    'AlienVault OTX Malware File Hashes')

    # Fetch and write malicious IPs  
    malicious_ips = fetch_malicious_ips(otx, days_back=60)
    if malicious_ips:
        write_cdb_list('otx-malicious-ips', malicious_ips, 
                    'AlienVault OTX Malicious IP Addresses')

    # Fetch and write malicious domains
    malicious_domains = fetch_malicious_domains(otx, days_back=60)
    if malicious_domains:
        write_cdb_list('otx-malicious-domains', malicious_domains, 
                    'AlienVault OTX Malicious Domains')

    
    logging.info("OTX threat intelligence update completed successfully")
    
    # Print summary
    total_indicators = len(malware_hashes) + len(malicious_ips) + len(malicious_domains)
    print(f"Summary:")
    print(f"- Malware Hashes: {len(malware_hashes)}")
    print(f"- Malicious IPs: {len(malicious_ips)}")
    print(f"- Malicious Domains: {len(malicious_domains)}")
    print(f"- Total Indicators: {total_indicators}")

if __name__ == "__main__":
    main()
{{- end }}

{{- define "wazuh.indexer.opensearchConfig"}}
cluster.name: ${CLUSTER_NAME}
node.name: ${NODE_NAME}
network.host: ${NETWORK_HOST}
discovery.seed_hosts: {{ include "wazuh.indexer.fullname" . }}-indexer-nodes
cluster.initial_master_nodes:
  - {{ include "wazuh.indexer.fullname" . }}-indexer-0

node.max_local_storage_nodes: "3"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
plugins.security.ssl.http.pemcert_filepath: /usr/share/wazuh-indexer/certs/node.pem
plugins.security.ssl.http.pemkey_filepath: /usr/share/wazuh-indexer/certs/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /usr/share/wazuh-indexer/certs/node.pem
plugins.security.ssl.transport.pemkey_filepath: /usr/share/wazuh-indexer/certs/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.authcz.admin_dn:
  - CN=admin,O={{ .Values.certificates.subject.organization }},L={{ .Values.certificates.subject.locality }},C={{ .Values.certificates.subject.country }}
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
  - CN={{ include "wazuh.indexer.fullname" . }}-indexer,O={{ .Values.certificates.subject.organization }},L={{ .Values.certificates.subject.locality }},C={{ .Values.certificates.subject.country }}
plugins.security.restapi.roles_enabled:
- "all_access"
- "security_rest_api_access"
plugins.security.allow_default_init_securityindex: true
cluster.routing.allocation.disk.threshold_enabled: false
compatibility.override_main_response_version: true
{{- end }}

{{- define "wazuh.indexer.internalUsers"}}
---
# This is the internal user database
# The hash value is a bcrypt hash and can be generated with plugin/tools/hash.sh

_meta:
  type: "internalusers"
  config_version: 2

# Define your internal users here

## Demo users
admin:
  hash: "{{ .Values.indexer.cred.passwordHash }}"
  reserved: true
  backend_roles:
  - "admin"
  description: "Demo admin user"

{{ .Values.dashboard.cred.username }}:
  hash: "{{ .Values.dashboard.cred.passwordHash }}"
  reserved: true
  description: "Demo {{ .Values.dashboard.cred.username }} user"

kibanaro:
  hash: "$2a$12$JJSXNfTowz7Uu5ttXfeYpeYE0arACvcwlPBStB1F.MI7f0U9Z4DGC"
  reserved: false
  backend_roles:
  - "kibanauser"
  - "readall"
  attributes:
    attribute1: "value1"
    attribute2: "value2"
    attribute3: "value3"
  description: "Demo kibanaro user"

logstash:
  hash: "$2a$12$u1ShR4l4uBS3Uv59Pa2y5.1uQuZBrZtmNfqB3iM/.jL0XoV9sghS2"
  reserved: false
  backend_roles:
  - "logstash"
  description: "Demo logstash user"

readall:
  hash: "$2a$12$ae4ycwzwvLtZxwZ82RmiEunBbIPiAmGZduBAjKN0TXdwQFtCwARz2"
  reserved: false
  backend_roles:
  - "readall"
  description: "Demo readall user"

snapshotrestore:
  hash: "$2y$12$DpwmetHKwgYnorbgdvORCenv4NAK8cPUg8AI6pxLCuWf/ALc0.v7W"
  reserved: false
  backend_roles:
  - "snapshotrestore"
  description: "Demo snapshotrestore user"
{{- end }}

{{- define "wazuh.indexer.rolesMapping"}}
---
# In this file users, backendroles and hosts can be mapped to Open Distro Security roles.
# Permissions for Opendistro roles are configured in roles.yml

_meta:
  type: "rolesmapping"
  config_version: 2

# Define your roles mapping here

## Default roles mapping

all_access:
  reserved: true
  hidden: false
  backend_roles:
    - "admin"
  {{- if .Values.dashboard.sso.oidc.roleMappings.allAccess.backendRoles }}
    {{- toYaml .Values.dashboard.sso.oidc.roleMappings.allAccess.backendRoles | nindent 4 }}
  {{- end }}
  {{- if .Values.dashboard.sso.saml.roleMappings.allAccess.backendRoles }}
    {{- toYaml .Values.dashboard.sso.saml.roleMappings.allAccess.backendRoles | nindent 4 }}
  {{- end }}
  hosts: []
  users: []
  and_backend_roles: []
  description: "Maps admin to all_access"

own_index:
  reserved: false
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - "*"
  and_backend_roles: []
  description: "Allow full access to an index named like the username"

logstash:
  reserved: false
  hidden: false
  backend_roles:
  - "logstash"
  hosts: []
  users: []
  and_backend_roles: []

readall:
  reserved: true
  hidden: false
  backend_roles:
  - "readall"
  hosts: []
  users: []
  and_backend_roles: []

manage_snapshots:
  reserved: true
  hidden: false
  backend_roles:
  - "snapshotrestore"
  hosts: []
  users: []
  and_backend_roles: []

kibana_server:
  reserved: true
  hidden: false
  {{- if .Values.dashboard.sso.oidc.roleMappings.kibanaServer.backendRoles }}
  backend_roles:
    {{- toYaml .Values.dashboard.sso.oidc.roleMappings.kibanaServer.backendRoles | nindent 4 }}
  {{- else }}
  backend_roles: []
  {{- end }}
  {{- if .Values.dashboard.sso.saml.roleMappings.kibanaServer.backendRoles }}
    {{- toYaml .Values.dashboard.sso.saml.roleMappings.kibanaServer.backendRoles | nindent 4 }}
  {{- end }}
  hosts: []
  users:
    - "{{ .Values.dashboard.cred.username }}"
  and_backend_roles: []

kibana_user:
  reserved: false
  hidden: false
  backend_roles:
    - "kibanauser"
  {{- if .Values.dashboard.sso.oidc.roleMappings.kibanaUser.backendRoles }}
    {{- toYaml .Values.dashboard.sso.oidc.roleMappings.kibanaUser.backendRoles | nindent 4 }}
  {{- end }}
  {{- if .Values.dashboard.sso.saml.roleMappings.kibanaUser.backendRoles }}
    {{- toYaml .Values.dashboard.sso.saml.roleMappings.kibanaUser.backendRoles | nindent 4 }}
  {{- end }}
  hosts: []
  users: []
  and_backend_roles: []
  description: "Maps kibanauser to kibana_user"

# Wazuh monitoring and statistics index permissions
manage_wazuh_index:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
    - "{{ .Values.dashboard.cred.username }}"
  and_backend_roles: []


{{- with .Values.dashboard.sso.oidc.extraRoleMappings }}
{{- toYaml . | nindent 0 }}
{{- end }}

{{- with .Values.dashboard.sso.saml.extraRoleMappings }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{- define "wazuh.indexer.roles"}}
_meta:
  type: "roles"
  config_version: 2

# Restrict users so they can only view visualization and dashboard on OpenSearchDashboards
kibana_read_only:
  reserved: true

# The security REST API access role is used to assign specific users access to change the security settings through the REST API.
security_rest_api_access:
  reserved: true

security_rest_api_full_access:
  reserved: true
  cluster_permissions:
    - 'restapi:admin/actiongroups'
    - 'restapi:admin/allowlist'
    - 'restapi:admin/config/update'
    - 'restapi:admin/internalusers'
    - 'restapi:admin/nodesdn'
    - 'restapi:admin/roles'
    - 'restapi:admin/rolesmapping'
    - 'restapi:admin/ssl/certs/info'
    - 'restapi:admin/ssl/certs/reload'
    - 'restapi:admin/tenants'

# Allows users to view monitors, destinations and alerts
alerting_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/alerting/alerts/get'
    - 'cluster:admin/opendistro/alerting/destination/get'
    - 'cluster:admin/opendistro/alerting/monitor/get'
    - 'cluster:admin/opendistro/alerting/monitor/search'
    - 'cluster:admin/opensearch/alerting/findings/get'
    - 'cluster:admin/opensearch/alerting/workflow/get'
    - 'cluster:admin/opensearch/alerting/workflow_alerts/get'

# Allows users to view and acknowledge alerts
alerting_ack_alerts:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/alerting/alerts/*'
    - 'cluster:admin/opendistro/alerting/chained_alerts/*'
    - 'cluster:admin/opendistro/alerting/workflow_alerts/*'

# Allows users to use all alerting functionality
alerting_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster_monitor'
    - 'cluster:admin/opendistro/alerting/*'
    - 'cluster:admin/opensearch/alerting/*'
    - 'cluster:admin/opensearch/notifications/feature/publish'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices_monitor'
        - 'indices:admin/aliases/get'
        - 'indices:admin/mappings/get'

# Allow users to read Anomaly Detection detectors and results
anomaly_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/ad/detector/info'
    - 'cluster:admin/opendistro/ad/detector/search'
    - 'cluster:admin/opendistro/ad/detectors/get'
    - 'cluster:admin/opendistro/ad/result/search'
    - 'cluster:admin/opendistro/ad/tasks/search'
    - 'cluster:admin/opendistro/ad/detector/validate'
    - 'cluster:admin/opendistro/ad/result/topAnomalies'

# Allows users to use all Anomaly Detection functionality
anomaly_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster_monitor'
    - 'cluster:admin/opendistro/ad/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices_monitor'
        - 'indices:admin/aliases/get'
        - 'indices:admin/mappings/get'

# Allow users to execute read only k-NN actions
knn_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/knn_search_model_action'
    - 'cluster:admin/knn_get_model_action'
    - 'cluster:admin/knn_stats_action'

# Allow users to use all k-NN functionality
knn_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/knn_training_model_action'
    - 'cluster:admin/knn_training_job_router_action'
    - 'cluster:admin/knn_training_job_route_decision_info_action'
    - 'cluster:admin/knn_warmup_action'
    - 'cluster:admin/knn_delete_model_action'
    - 'cluster:admin/knn_remove_model_from_cache_action'
    - 'cluster:admin/knn_update_model_graveyard_action'
    - 'cluster:admin/knn_search_model_action'
    - 'cluster:admin/knn_get_model_action'
    - 'cluster:admin/knn_stats_action'

# Allow users to execute read only ip2geo datasource action
ip2geo_datasource_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/geospatial/datasource/get'

# Allow users to use all ip2geo datasource action
ip2geo_datasource_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/geospatial/datasource/*'

# Allows users to read Notebooks
notebooks_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/notebooks/list'
    - 'cluster:admin/opendistro/notebooks/get'

# Allows users to all Notebooks functionality
notebooks_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/notebooks/create'
    - 'cluster:admin/opendistro/notebooks/update'
    - 'cluster:admin/opendistro/notebooks/delete'
    - 'cluster:admin/opendistro/notebooks/get'
    - 'cluster:admin/opendistro/notebooks/list'

# Allows users to read observability objects
observability_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/observability/get'

# Allows users to all Observability functionality
observability_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/observability/create'
    - 'cluster:admin/opensearch/observability/update'
    - 'cluster:admin/opensearch/observability/delete'
    - 'cluster:admin/opensearch/observability/get'

# Allows users to all PPL functionality
ppl_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/ppl'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:admin/mappings/get'
        - 'indices:data/read/search*'
        - 'indices:monitor/settings/get'

# Allows users to read and download Reports
reports_instances_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to read and download Reports and Report-definitions
reports_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/definition/get'
    - 'cluster:admin/opendistro/reports/definition/list'
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to all Reports functionality
reports_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/definition/create'
    - 'cluster:admin/opendistro/reports/definition/update'
    - 'cluster:admin/opendistro/reports/definition/on_demand'
    - 'cluster:admin/opendistro/reports/definition/delete'
    - 'cluster:admin/opendistro/reports/definition/get'
    - 'cluster:admin/opendistro/reports/definition/list'
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to use all asynchronous-search functionality
asynchronous_search_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/asynchronous_search/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:data/read/search*'

# Allows users to read stored asynchronous-search results
asynchronous_search_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/asynchronous_search/get'

# Allows user to use all index_management actions - ism policies, rollups, transforms
index_management_full_access:
  reserved: true
  cluster_permissions:
    - "cluster:admin/opendistro/ism/*"
    - "cluster:admin/opendistro/rollup/*"
    - "cluster:admin/opendistro/transform/*"
    - "cluster:admin/opensearch/controlcenter/lron/*"
    - "cluster:admin/opensearch/notifications/channels/get"
    - "cluster:admin/opensearch/notifications/feature/publish"
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:admin/opensearch/ism/*'

# Allows users to use all cross cluster replication functionality at leader cluster
cross_cluster_replication_leader_full_access:
  reserved: true
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - "indices:admin/plugins/replication/index/setup/validate"
        - "indices:data/read/plugins/replication/changes"
        - "indices:data/read/plugins/replication/file_chunk"

# Allows users to use all cross cluster replication functionality at follower cluster
cross_cluster_replication_follower_full_access:
  reserved: true
  cluster_permissions:
    - "cluster:admin/plugins/replication/autofollow/update"
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - "indices:admin/plugins/replication/index/setup/validate"
        - "indices:data/write/plugins/replication/changes"
        - "indices:admin/plugins/replication/index/start"
        - "indices:admin/plugins/replication/index/pause"
        - "indices:admin/plugins/replication/index/resume"
        - "indices:admin/plugins/replication/index/stop"
        - "indices:admin/plugins/replication/index/update"
        - "indices:admin/plugins/replication/index/status_check"

# Allows users to use all cross cluster search functionality at remote cluster
cross_cluster_search_remote_full_access:
  reserved: true
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:admin/shards/search_shards'
        - 'indices:data/read/search'

# Allow users to read ML stats/models/tasks
ml_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/ml/stats/nodes'
    - 'cluster:admin/opensearch/ml/model_groups/search'
    - 'cluster:admin/opensearch/ml/models/get'
    - 'cluster:admin/opensearch/ml/models/search'
    - 'cluster:admin/opensearch/ml/tasks/get'
    - 'cluster:admin/opensearch/ml/tasks/search'

# Allows users to use all ML functionality
ml_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster_monitor'
    - 'cluster:admin/opensearch/ml/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices_monitor'

# Allows users to use all Notifications functionality
notifications_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/notifications/*'

# Allows users to read Notifications config/channels
notifications_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/notifications/configs/get'
    - 'cluster:admin/opensearch/notifications/features'
    - 'cluster:admin/opensearch/notifications/channels/get'

# Allows users to use all snapshot management functionality
snapshot_management_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/snapshot_management/*'
    - 'cluster:admin/opensearch/notifications/feature/publish'
    - 'cluster:admin/repository/*'
    - 'cluster:admin/snapshot/*'

# Allows users to see snapshots, repositories, and snapshot management policies
snapshot_management_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/snapshot_management/policy/get'
    - 'cluster:admin/opensearch/snapshot_management/policy/search'
    - 'cluster:admin/opensearch/snapshot_management/policy/explain'
    - 'cluster:admin/repository/get'
    - 'cluster:admin/snapshot/get'

# Allows user to use point in time functionality
point_in_time_full_access:
  reserved: true
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'manage_point_in_time'

# Allows users to see security analytics detectors and others
security_analytics_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/securityanalytics/alerts/get'
    - 'cluster:admin/opensearch/securityanalytics/correlations/findings'
    - 'cluster:admin/opensearch/securityanalytics/correlations/list'
    - 'cluster:admin/opensearch/securityanalytics/detector/get'
    - 'cluster:admin/opensearch/securityanalytics/detector/search'
    - 'cluster:admin/opensearch/securityanalytics/findings/get'
    - 'cluster:admin/opensearch/securityanalytics/mapping/get'
    - 'cluster:admin/opensearch/securityanalytics/mapping/view/get'
    - 'cluster:admin/opensearch/securityanalytics/rule/get'
    - 'cluster:admin/opensearch/securityanalytics/rule/search'

# Allows users to use all security analytics functionality
security_analytics_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/securityanalytics/alerts/*'
    - 'cluster:admin/opensearch/securityanalytics/correlations/*'
    - 'cluster:admin/opensearch/securityanalytics/detector/*'
    - 'cluster:admin/opensearch/securityanalytics/findings/*'
    - 'cluster:admin/opensearch/securityanalytics/mapping/*'
    - 'cluster:admin/opensearch/securityanalytics/rule/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:admin/mapping/put'
        - 'indices:admin/mappings/get'

# Allows users to view and acknowledge alerts
security_analytics_ack_alerts:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/securityanalytics/alerts/*'

# Wazuh monitoring and statistics index permissions
manage_wazuh_index:
  reserved: true
  hidden: false
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - "wazuh-*"
    dls: ""
    fls: []
    masked_fields: []
    allowed_actions:
    - "read"
    - "delete"
    - "manage"
    - "index"
  tenant_permissions: []
  static: false
{{- end }}

{{- define "wazuh.indexer.securityConfig"}}
---

# This is the main OpenSearch Security configuration file where authentication
# and authorization is defined.
#
# You need to configure at least one authentication domain in the authc of this file.
# An authentication domain is responsible for extracting the user credentials from
# the request and for validating them against an authentication backend like Active Directory for example.
#
# If more than one authentication domain is configured the first one which succeeds wins.
# If all authentication domains fail then the request is unauthenticated.
# In this case an exception is thrown and/or the HTTP status is set to 401.
#
# After authentication authorization (authz) will be applied. There can be zero or more authorizers which collect
# the roles from a given backend for the authenticated user.
#
# Both, authc and auth can be enabled/disabled separately for REST and TRANSPORT layer. Default is true for both.
#        http_enabled: true
#        transport_enabled: true
#
# For HTTP it is possible to allow anonymous authentication. If that is the case then the HTTP authenticators try to
# find user credentials in the HTTP request. If credentials are found then the user gets regularly authenticated.
# If none can be found the user will be authenticated as an "anonymous" user. This user has always the username "anonymous"
# and one role named "anonymous_backendrole".
# If you enable anonymous authentication all HTTP authenticators will not challenge.
#
#
# Note: If you define more than one HTTP authenticators make sure to put non-challenging authenticators like "proxy" or "clientcert"
# first and the challenging one last.
# Because it's not possible to challenge a client with two different authentication methods (for example
# Kerberos and Basic) only one can have the challenge flag set to true. You can cope with this situation
# by using pre-authentication, e.g. sending a HTTP Basic authentication header in the request.
#
# Default value of the challenge flag is true.
#
#
# HTTP
#   basic (challenging)
#   proxy (not challenging, needs xff)
#   kerberos (challenging)
#   clientcert (not challenging, needs https)
#   jwt (not challenging)
#   host (not challenging) #DEPRECATED, will be removed in a future version.
#                          host based authentication is configurable in roles_mapping

# Authc
#   internal
#   noop
#   ldap

# Authz
#   ldap
#   noop



_meta:
  type: "config"
  config_version: 2

config:
  dynamic:
    # Set filtered_alias_mode to 'disallow' to forbid more than 2 filtered aliases per index
    # Set filtered_alias_mode to 'warn' to allow more than 2 filtered aliases per index but warns about it (default)
    # Set filtered_alias_mode to 'nowarn' to allow more than 2 filtered aliases per index silently
    #filtered_alias_mode: warn
    #do_not_fail_on_forbidden: false
    #kibana:
    # Kibana multitenancy
    #multitenancy_enabled: true
    #private_tenant_enabled: true
    #default_tenant: ""
    #server_username: kibanaserver
    #index: '.kibana'
    http:
      anonymous_auth_enabled: false
      xff:
        enabled: false
        internalProxies: '192\.168\.0\.10|192\.168\.0\.11' # regex pattern
        #internalProxies: '.*' # trust all internal proxies, regex pattern
        #remoteIpHeader:  'x-forwarded-for'
        ###### see https://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html for regex help
        ###### more information about XFF https://en.wikipedia.org/wiki/X-Forwarded-For
        ###### and here https://tools.ietf.org/html/rfc7239
        ###### and https://tomcat.apache.org/tomcat-8.0-doc/config/valve.html#Remote_IP_Valve
    authc:
      {{- if .Values.dashboard.sso.oidc.enabled }}
      openid_auth_domain:
        http_enabled: true
        transport_enabled: true
        order: {{ .Values.dashboard.sso.oidc.order }}
        http_authenticator:
          type: openid
          challenge: {{ not .Values.dashboard.sso.oidc.primary }}
          config:
            subject_key: {{ .Values.dashboard.sso.oidc.config.subjectKey }}
            roles_key: {{ .Values.dashboard.sso.oidc.config.rolesKey }}
            openid_connect_url: {{ .Values.dashboard.sso.oidc.url }}
            {{- with .Values.dashboard.sso.oidc.issuer }}
            required_issuer: {{ . }}
            {{- end }}
            {{- if .Values.dashboard.sso.oidc.idp.enableSSL }}
            openid_connect_idp:
              enable_ssl: {{ .Values.dashboard.sso.oidc.idp.enableSSL }}
              pemtrustedcas_filepath: {{ .Values.dashboard.sso.oidc.idp.pemtrustedcasFilePath }}
            {{- end }}
            client_id: ${env.OPENSEARCH_OIDC_CLIENT_ID}
            client_secret: ${env.OPENSEARCH_OIDC_CLIENT_SECRET}
        authentication_backend:
          type: noop
      {{- end }}
      {{- if .Values.dashboard.sso.saml.enabled }}
      saml_auth_domain:
        http_enabled: true
        transport_enabled: false
        order: {{ .Values.dashboard.sso.saml.order }}
        http_authenticator:
          type: saml
          challenge: {{ not .Values.dashboard.sso.saml.primary }}
          config:
            idp:
              metadata_url: {{ required "dashboard.sso.saml.metadataUrl is required" .Values.dashboard.sso.saml.metadataUrl }}
              entity_id: {{ required "dashboard.sso.saml.idpEntityId is required" .Values.dashboard.sso.saml.idpEntityId }}
            sp:
              entity_id: {{ .Values.dashboard.sso.saml.spEntityId }}
            kibana_url: {{ .Values.dashboard.sso.saml.kibanaUrl | default (printf "https://%s" .Values.dashboard.ingress.host) | required "dashboard.sso.saml.kibanaUrl or dashboard.ingress.host is required" }}
            roles_key: {{ .Values.dashboard.sso.saml.config.rolesKey }}
            exchange_key: {{ required "dashboard.sso.saml.exchangeKey is required" .Values.dashboard.sso.saml.exchangeKey }}
        authentication_backend:
          type: noop
      {{- end }}
      kerberos_auth_domain:
        http_enabled: false
        transport_enabled: false
        order: 6
        http_authenticator:
          type: kerberos
          challenge: true
          config:
            # If true a lot of kerberos/security related debugging output will be logged to standard out
            krb_debug: false
            # If true then the realm will be stripped from the user name
            strip_realm_from_principal: true
        authentication_backend:
          type: noop
      basic_internal_auth_domain:
        description: "Authenticate via HTTP Basic against internal users database"
        http_enabled: true
        transport_enabled: true
        order: {{ .Values.dashboard.basicAuth.order }}
        http_authenticator:
          type: basic
          challenge: {{ .Values.dashboard.basicAuth.challenge }}
        authentication_backend:
          type: intern
      proxy_auth_domain:
        description: "Authenticate via proxy"
        http_enabled: false
        transport_enabled: false
        order: 3
        http_authenticator:
          type: proxy
          challenge: false
          config:
            user_header: "x-proxy-user"
            roles_header: "x-proxy-roles"
        authentication_backend:
          type: noop
      jwt_auth_domain:
        description: "Authenticate via Json Web Token"
        http_enabled: false
        transport_enabled: false
        order: 0
        http_authenticator:
          type: jwt
          challenge: false
          config:
            signing_key: "base64 encoded HMAC key or public RSA/ECDSA pem key"
            jwt_header: "Authorization"
            jwt_url_parameter: null
            jwt_clock_skew_tolerance_seconds: 30
            roles_key: null
            subject_key: null
        authentication_backend:
          type: noop
      clientcert_auth_domain:
        description: "Authenticate via SSL client certificates"
        http_enabled: false
        transport_enabled: false
        order: 2
        http_authenticator:
          type: clientcert
          config:
            username_attribute: cn #optional, if omitted DN becomes username
          challenge: false
        authentication_backend:
          type: noop
      ldap:
        description: "Authenticate via LDAP or Active Directory"
        http_enabled: false
        transport_enabled: false
        order: 5
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          # LDAP authentication backend (authenticate users against a LDAP or Active Directory)
          type: ldap
          config:
            # enable ldaps
            enable_ssl: false
            # enable start tls, enable_ssl should be false
            enable_start_tls: false
            # send client certificate
            enable_ssl_client_auth: false
            # verify ldap hostname
            verify_hostnames: true
            hosts:
            - localhost:8389
            bind_dn: null
            password: null
            userbase: 'ou=people,dc=example,dc=com'
            # Filter to search for users (currently in the whole subtree beneath userbase)
            # {0} is substituted with the username
            usersearch: '(sAMAccountName={0})'
            # Use this attribute from the user as username (if not set then DN is used)
            username_attribute: null
    authz:
      roles_from_myldap:
        description: "Authorize via LDAP or Active Directory"
        http_enabled: false
        transport_enabled: false
        authorization_backend:
          # LDAP authorization backend (gather roles from a LDAP or Active Directory, you have to configure the above LDAP authentication backend settings too)
          type: ldap
          config:
            # enable ldaps
            enable_ssl: false
            # enable start tls, enable_ssl should be false
            enable_start_tls: false
            # send client certificate
            enable_ssl_client_auth: false
            # verify ldap hostname
            verify_hostnames: true
            hosts:
            - localhost:8389
            bind_dn: null
            password: null
            rolebase: 'ou=groups,dc=example,dc=com'
            # Filter to search for roles (currently in the whole subtree beneath rolebase)
            # {0} is substituted with the DN of the user
            # {1} is substituted with the username
            # {2} is substituted with an attribute value from user's directory entry, of the authenticated user. Use userroleattribute to specify the name of the attribute
            rolesearch: '(member={0})'
            # Specify the name of the attribute which value should be substituted with {2} above
            userroleattribute: null
            # Roles as an attribute of the user entry
            userrolename: disabled
            #userrolename: memberOf
            # The attribute in a role entry containing the name of that role, Default is "name".
            # Can also be "dn" to use the full DN as rolename.
            rolename: cn
            # Resolve nested roles transitive (roles which are members of other roles and so on ...)
            resolve_nested_roles: true
            userbase: 'ou=people,dc=example,dc=com'
            # Filter to search for users (currently in the whole subtree beneath userbase)
            # {0} is substituted with the username
            usersearch: '(uid={0})'
            # Skip users matching a user name, a wildcard or a regex pattern
            #skip_users:
            #  - 'cn=Michael Jackson,ou*people,o=TEST'
            #  - '/\S*/'
      roles_from_another_ldap:
        description: "Authorize via another Active Directory"
        http_enabled: false
        transport_enabled: false
        authorization_backend:
          type: ldap
          #config goes here ...
  #    auth_failure_listeners:
  #      ip_rate_limiting:
  #        type: ip
  #        allowed_tries: 10
  #        time_window_seconds: 3600
  #        block_expiry_seconds: 600
  #        max_blocked_clients: 100000
  #        max_tracked_clients: 100000
  #      internal_authentication_backend_limiting:
  #        type: username
  #        authentication_backend: intern
  #        allowed_tries: 10
  #        time_window_seconds: 3600
  #        block_expiry_seconds: 600
  #        max_blocked_clients: 100000
  #        max_tracked_clients: 100000
{{- end }}

{{/*
Sysctl set if less then
*/}}
{{- define "wazuh.sysctlIfLess" -}}
CURRENT=`sysctl -n {{ .key }}`;
DESIRED="{{ .value }}";
if [ "$DESIRED" -gt "$CURRENT" ]; then
    sysctl -w {{ .key }}={{ .value }};
fi;
{{- end -}}

{{/*
Get port value from ports array by name
*/}}
{{- define "wazuh.getPortByName" -}}
{{- $portName := .portName -}}
{{- $ports := .ports -}}
{{- range $ports -}}
{{- if eq .name $portName -}}
{{- .port -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Define serviceaccount names
*/}}
{{- define "wazuh.indexer.serviceAccountName" -}}
{{- if .Values.indexer.serviceAccount.create -}}
    {{ default (printf "%s-indexer" (include "wazuh.indexer.fullname" .)) .Values.indexer.serviceAccount.name }}
{{- else -}}
    {{ "default" }}
{{- end -}}
{{- end -}}

{{- define "wazuh.dashboard.serviceAccountName" -}}
{{- if .Values.dashboard.serviceAccount.create -}}
    {{ default (printf "%s-dashboard" (include "wazuh.fullname" .)) .Values.dashboard.serviceAccount.name }}
{{- else -}}
    {{ "default" }}
{{- end -}}
{{- end -}}

{{- define "wazuh.manager.serviceAccountName" -}}
{{- if .Values.wazuh.serviceAccount.create -}}
    {{ default (printf "%s-manager" (include "wazuh.fullname" .)) .Values.wazuh.serviceAccount.name }}
{{- else -}}
    {{ "default" }}
{{- end -}}
{{- end -}}

{{- define "wazuh.agent.serviceAccountName" -}}
{{- if .Values.agent.serviceAccount.create -}}
    {{ default (printf "%s-agent" (include "wazuh.fullname" .)) .Values.agent.serviceAccount.name }}
{{- else -}}
    {{ "default" }}
{{- end -}}
{{- end -}}
