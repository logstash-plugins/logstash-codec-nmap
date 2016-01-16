# encoding: utf-8
require "logstash/codecs/base"
require "nmap/xml"
require 'securerandom'

# This codec may be used to decode (via inputs) only.
# It decodes nmap generated XML and outputs each host as its own event

class LogStash::Codecs::Nmap < LogStash::Codecs::Base
  config_name "nmap"

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

    xml.hosts.each_with_index do |host,idx|
      # Convert the host to a 'base' host event
      # This will be used for the later port/hop types
      base = hashify_host(host, xml)

      # Add some scanner-wide attributes
      base['arguments'] = xml.scanner.arguments
      base['version'] = xml.scanner.version
      base['scan_id'] = scan_id

      # Pull out the detail
      ports = host.ports.map {|p| hashify_port(p)}
      traceroute = hashify_traceroute(host.traceroute)

      scan_host_id = scan_id + "-h#{idx}"

      if @emit_ports && ports
        ports.each.with_index do |port,idx|
          yield LogStash::Event.new(base.merge(
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
          yield LogStash::Event.new(base.merge(
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
        yield LogStash::Event.new(base.merge(
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
      'hostname' => service.hostname, # This is just a string
      'device_type' => service.device_type,
      'fingerprint_method' => service.fingerprint_method.to_s,
      'fingerprint' => service.fingerprint,
      'confidence' => service.confidence
    }
  end

  def hashify_port(port)
    return unless port

    {
      'number' => port.number,
      'reason' => port.reason,
      'protocol' => port.protocol.to_s,
      'service' => hashify_service(port.service),
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
    Hash[struct.each_pair.map {|k,v| [k, de_keyword(v)]}]
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
