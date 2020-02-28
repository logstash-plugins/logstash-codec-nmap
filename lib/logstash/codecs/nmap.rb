# encoding: utf-8
require "logstash/codecs/base"
require "nmap/xml"
require 'securerandom'

# This codec is used to parse https://nmap.org/[namp] output data which is serialized in XML format. Nmap ("Network Mapper") is a free and open source utility for network discovery and security auditing.
# For more information on nmap, see https://nmap.org/.
#
# This codec can only be used for decoding data.
#
# Event types are listed below
#
# `nmap_scan_metadata`: An object containing top level information about the scan, including how many hosts were up, and how many were down. Useful for the case where you need to check if a DNS based hostname does not resolve, where both those numbers will be zero.
# `nmap_host`: One event is created per host. The full data covering an individual host, including open ports and traceroute information as a nested structure.
# `nmap_port`: One event is created per host/port. This duplicates data already in `nmap_host`: This was put in for the case where you want to model ports as separate documents in Elasticsearch (which Kibana prefers).
# `nmap_traceroute_link`: One of these is output per traceroute 'connection', with a `from` and a `to` object describing each hop. Note that traceroute hop data is not always correct due to the fact that each tracing ICMP packet may take a different route. Also very useful for Kibana visualizations.

class LogStash::Codecs::Nmap < LogStash::Codecs::Base
  config_name "nmap"

  # Emit scan metadata
  config :emit_scan_metadata, :validate => :boolean, :default => true
  # Emit all host data as a nested document (including ports + traceroutes) with the type 'nmap_fullscan'
  config :emit_hosts, :validate => :boolean, :default => true
  # Emit each port as a separate document with type 'nmap_port'
  config :emit_ports, :validate => :boolean, :default => true
  # Emit each hop_tuple of the traceroute with type 'nmap_traceroute_link'
  config :emit_traceroute_links, :validate => :boolean, :default => true

  public
  def register
  end

  public
  def decode(data)
    xml = Nmap::XML.parse(data)
    scan_id = SecureRandom.uuid

    base = {}
    base['arguments'] = xml.scanner.arguments
    base['version'] = xml.scanner.version
    base['scan_id'] = scan_id

    # This really needs to be put into ruby-nmap
    scan_host_stats = Hash[xml.instance_variable_get(:@doc).xpath('/nmaprun[@scanner="nmap"]/runstats/hosts').first.attributes.map {|k,v| [k,v.value.to_i]}]

    finished_info = Hash[xml.instance_variable_get(:@doc).xpath('/nmaprun[@scanner="nmap"]/runstats/finished').first.attributes.map {|k,v| [k,v.value] }]
    finished_info["elapsed"] = finished_info["elapsed"].to_f
    finished_info["time"] = timeify(Time.at(finished_info["time"].to_i))

    run_stats = hashify_struct(xml.run_stats.first)
    run_stats["finished"] = finished_info

    if @emit_scan_metadata
        yield LogStash::Event.new(base.merge({
          'id' => scan_id,
          'type' => 'nmap_scan_metadata',
          'host_stats' => scan_host_stats,
          'start_time' => timeify(xml.scanner.start_time),
          'end_time' => run_stats["finished"]["time"],
          'run_stats' =>  hashify_run_stats(xml.run_stats.first)
        }))
    end

    xml.hosts.each_with_index do |host,idx|
      # Convert the host to a 'host_base' host event
      # This will be used for the later port/hop types
      host_base = hashify_host(host, xml).merge(base)


      # Pull out the detail
      ports = host.ports.map {|p| hashify_port(p)}
      traceroute = hashify_traceroute(host.traceroute)
      scan_host_id = scan_id + "-h#{idx}"

      if @emit_ports && ports
        ports.each.with_index do |port,idx|
          yield LogStash::Event.new(host_base.merge(
            'type' => 'nmap_port',
            'port' => port,
            'scan_host_id' => scan_host_id,
            'id' => scan_host_id+"-p#{idx}"
          ))

        end
      end

      if @emit_traceroute_links && traceroute && (hops = traceroute['hops'])
        hops.each_with_index do |hop,idx|
          next_hop = hops[idx+1]
          yield LogStash::Event.new(host_base.merge(
            'type' =>'nmap_traceroute_link',
            'from' => hop,
            'to' => next_hop,
            'rtt_diff' => (next_hop ? next_hop['rtt'] - hop['rtt'] : nil),
            'scan_host_id' => scan_host_id,
            'id' => scan_host_id+"-tl#{idx}"
          ))
        end
      end

      if @emit_hosts
        yield LogStash::Event.new(host_base.merge(
          'type' => 'nmap_host',
          'ports' => ports,
          'traceroute' => traceroute,
          'id' => scan_host_id
        ))
      end
    end
  rescue StandardError => e
    raise e
    @logger.warn("An unexpected error occurred parsing nmap XML",
                 :input => data,
                 :message => e.message,
                 :class => e.class.name,
                 :backtrace => e.backtrace)
  end

  def hashify_host(host, xml)
    scan_start = timeify(xml.scanner.start_time)

    h = {}
    h['start_time'] = timeify(host.start_time, scan_start)
    h['end_time'] = timeify(host.end_time, scan_start)

    # Needs to be pached in ruby-nmap
    times = host.instance_variable_get(:@node).xpath("times").first
    h['times'] = Hash[times.first.map {|k,v| [k,v.to_i]}] if times

    # These two are actually different.
    # Address may contain a MAC, addresses will not AFAICT
    h['addresses'] = hashify_structs(host.addresses)
    h['address'] = host.address # str

    h['ip'] = host.ip # str
    h['ipv4'] = host.ipv4 # str
    h['ipv6'] = host.ipv6 # str
    h['mac'] = host.mac # str
    h['status'] = hashify_status(host.status)
    h['hostname'] = hashify_hostname(host.hostname)
    h['uptime'] = hashify_uptime(host.uptime)
    h['os'] = hashify_os(host.os)

    h
  end

  def hashify_run_stats(run_stats)
    h = hashify_struct(run_stats)
    h["elapsed"] = h["elapsed"].to_f
    h
  end

  def hashify_status(status)
    return unless status

    {
      'state' => status.state.to_s, # str
      'reason' => status.reason # str
    }
  end

  def hashify_hostname(hostname)
    return unless hostname

    {
      'name' => hostname.name, # str
      'type' => hostname.type, # str
    }
  end

  def hashify_os(os)
    return unless os

    # we need this nil guard here till https://github.com/sophsec/ruby-nmap/pull/41 is accepted
    fingerprint = os.fingerprint rescue nil
    {
      'ports_used' => os.ports_used,
      'fingerprint' => fingerprint,
      'classes' => hashify_os_classes(os.classes),
      'matches' => hashify_structs(os.matches)
    }
  end

  def hashify_os_classes(classes)
    return if !classes || classes.empty?

    classes.map do |klass|
      {
        'type' => klass.type.to_s, # returned as sym originally
        'vendor' => klass.vendor.to_s,
        'family' => klass.family.to_s,
        'gen' => klass.gen.to_s,
        'accuracy' => klass.accuracy # int
      }
    end
  end

  def hashify_uptime(uptime)
    return unless uptime

    {
      'seconds' => uptime.seconds,
      'last_boot' => timeify(uptime.last_boot)
    }
  end

  def hashify_service(service)
    return unless service

    protocol = service.protocol rescue nil
    {
      'name' => service.name,
      'ssl' => service.ssl?,
      'protocol' => protocol,
      'product' => service.product,
      'version' => service.version,
      'hostname' => service.hostname, # This is just a string
      'device_type' => service.device_type,
      'fingerprint_method' => service.fingerprint_method.to_s,
      'fingerprint' => service.fingerprint,
      'confidence' => service.confidence
    }
  end

  def hashify_script(script)
    return unless script

    script.each do |key,value|
      {
        script['id'] => script['output']  #str
      }
    end
  end

  def hashify_port(port)
    return unless port

    {
      'number' => port.number,
      'reason' => port.reason,
      'protocol' => port.protocol.to_s,
      'service' => hashify_service(port.service),
      'script' => hashify_script(port.scripts),
      'state' => port.state.to_s
    }
  end

  def hashify_traceroute(traceroute)
    return unless traceroute

    protocol = traceroute.protocol rescue nil
    {
      'port' => traceroute.port, # int
      'protocol' => protocol,
      'hops' => traceroute.map.with_index do |hop, idx|
        {
          'address' => hop.addr, # str
          'hostname' => hop.host, # str
          'ttl' => hop.ttl.to_i, # int
          'rtt' => hop.rtt.to_i, # int
          'index' => idx # int (for searching by distance)
        }
      end
    }
  end

  def hashify_structs(structs)
    structs.map {|s| hashify_struct(s)}
  end

  def hashify_struct(struct)
    Hash[struct.each_pair.map {|k,v| [de_keyword(k), de_keyword(v)]}]
  end

  def de_keyword(value)
    value.is_a?(Symbol) ? value.to_s : value
  end

  EPOCH = LogStash::Timestamp.new(Time.at(0))
  def timeify(time, default=nil)
    timestamp = time ? LogStash::Timestamp.new(time) : nil
    # Sometimes the nmap parser returns the epoch when there's no time...
    if (!timestamp || timestamp <= EPOCH)
      default
    else
      timestamp
    end
  end

  # Some strings have quoted values, we may want to remove leading/trailing quotes
  def dequote(str)
    return nil unless str
    str.gsub(/\A"|"\Z/, '')
  end

end
