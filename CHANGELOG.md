## 0.0.22
  - [DOC] Fixed typo: changed `namp` to `nmap` [#32](https://github.com/logstash-plugins/logstash-codec-nmap/pull/32)

## 0.0.21
  - Update gemspec summary

## 0.0.20
  - Fix some documentation issues

# 0.0.18
  - Fix bug in 0.0.17 that prevented this from working with LS 5.x
# 0.0.17
  - Expand logstash-core-api constraints to allow for 5.2 functionality
# 0.0.16
  - Pin ruby-nmap version to 0.8.0 to avoid needing ruby 2.0+
# 0.0.15
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
# 0.0.14
  - New dependency requirements for logstash-core for the 5.0 release
## 0.0.13
  - Actually include 'times' element
## 0.0.12
  - Improve mapping examples
  - Fix IDs for nmap_scan_metadata
## 0.0.11
  - Add start/end times for nmap_scan_metadata documents
## 0.0.10
  - Add top level metadata object
  - Improve examples
