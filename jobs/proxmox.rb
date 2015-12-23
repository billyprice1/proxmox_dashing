require 'json'
require 'rest_client'
require 'socket'
require 'timeout'
require 'yaml'

set :kvm_rows, []

def get_node_kernel(node,site,auth_params)
  site["nodes/#{node}/status"].get auth_params do |response, request, result, &block|
    JSON.parse(response.body)['data']['kversion'].split[1]
  end
end

def get_data(site,auth_params)
  site["cluster/status"].get auth_params do |response, request, result, &block|
    JSON.parse(response.body)['data']
  end
end

def extract_ticket(response)
  data = JSON.parse(response.body)
  ticket = data['data']['ticket']
  csrf_prevention_token = data['data']['CSRFPreventionToken']
  unless ticket.nil?
    token = 'PVEAuthCookie=' + ticket.gsub!(/:/, '%3A').gsub!(/=/, '%3D')
  end
  @connection_status = 'connected'
  {
    CSRFPreventionToken: csrf_prevention_token,
    cookie: token
  }
end

def have_quorum(status)
  quorum_line = status.find { |a| a['type'] == 'quorum'}
  quorate = quorum_line['quorate'].to_i
  if quorate == 0
    false
  else
    true
  end
end

def select_hosts(nodes, attribute, value=0)
    nodes_array = nodes.select { |a| a[attribute] == value }
    nodes_array.map { |x| x["name"] }
end

def is_listening?(hostname)
  uri       = "https://#{hostname}:8006/api2/json/"
  RestClient::Resource.new(uri, :verify_ssl => false, open_timeout: 3)
end

def is_port_open?(ip, port)
  begin
    Timeout::timeout(1) do
      begin
        s = TCPSocket.new(ip, port)
        s.close
        return true
      rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
        return false
      end
    end
  rescue Timeout::Error
  end
  false
end

def get_config
  #config_file = File.dirname(File.expand_path(__FILE__)) + '/../../shared/proxmox_dashing/config.yml'
  config_file = '/tmp/config.yml'
  config = YAML::load(File.open(config_file))
  config.each_key do |cluster|
    config[cluster]['bad_nodes']  = {}
    config[cluster]['good_nodes'] = []
  end
  return config
end

def classify_nodes(config,cluster)
  p "CLUSTER HOSTS #{config[cluster]['proxmox_hosts']}"
  config[cluster]['proxmox_hosts'].each do |host|
    if is_port_open?(host,config[cluster]['port'])
      uri       = "https://#{host}:#{config[cluster]['port']}/api2/json/"
      post_param = { username: config[cluster]['username'], realm: config[cluster]['realm'], password: config[cluster]['password'] }
      begin
        site = RestClient::Resource.new(uri, :verify_ssl => false, open_timeout: 3)
        site['access/ticket'].post post_param do |response, request, result, &block|
          if response.code == 200
            config[cluster]['bad_nodes'].delete(host) if config[cluster]['bad_nodes'].include?(host)
            config[cluster]['good_nodes'] << host unless config[cluster]['good_nodes'].include?(host)
          else
            config[cluster]['good_nodes'].delete(host) if config[cluster]['good_nodes'].include?(host)
            config[cluster]['bad_nodes'][host] = "cannot authenticate"
          end
        end
      rescue Exception
        config[cluster]['good_nodes'].delete(host) if config[cluster]['good_nodes'].include?(host)
        config[cluster]['bad_nodes'][host] = "cannot authenticate"
      end
    else
      config[cluster]['good_nodes'].delete(host) if config[cluster]['good_nodes'].include?(host)
        config[cluster]['bad_nodes'][host] = "not listening"
    end
    config
  end
end

def report_cluster_status(site,auth_params)
  cluster_status = get_data(site,auth_params)
	nodes = []
  nodes = cluster_status.select { |a| a['type'] == 'node'}

  norgmanagerlist = select_hosts(nodes,'rgmanager',0)
  downhostlist = select_hosts(nodes, 'state',0)
  nopmxcfshostlist = select_hosts(nodes, 'pmxcfs',0)

  ha_hosts_array = cluster_status.select { |a| a['type'] == 'group'}
  down_ha_hosts = ha_hosts_array.select { |a| a['state'] != '112' }
  down_ha_host_ids = down_ha_hosts.map { |x| x["name"] }

  send_event('pvecluster', { state: 'critical', message: "Too many nodes not running pvecluster: #{nopmxcfshostlist.join(", ")}" } ) if nopmxcfshostlist.size >= 2
  if nopmxcfshostlist.empty?
    send_event('pvecluster', { state: 'ok', message: 'Cluster has quorum' } )
  else
    send_event('pvecluster', { state: 'warning', message: "PVECluster not running on:\n #{nopmxcfshostlist.join(", ")}"} )
  end

  send_event('corosync', { state: 'critical', message: 'Cluster lost quorum', status:'Critical' } ) unless have_quorum(cluster_status)
  if downhostlist.empty?
    send_event('corosync', { state: 'ok', message: "Corosync up on all hosts"} )
  else
    send_event('corosync', { state: 'warning', message: "Node(s) not running: \n #{downhostlist.join(", ")}" } )
  end
  unless norgmanagerlist.empty?
    if nodes.count.to_f/2 > norgmanagerlist.count.to_f
      state_level = "warning"
    else
      state_level = "critical"
    end
    send_event('rgmanager', { state: state_level, message: "Node(s) not running RG Manager: \n #{norgmanagerlist.join(", ")}" } )
  else
    send_event('rgmanager', { state: 'ok', message: 'RGmanager is healthy' } )
  end

  unless down_ha_host_ids.empty?
    send_event('haservers', { state: 'critical', message: "HA servers down: \n #{down_ha_host_ids.join(", ")}" } )
  else
    send_event('haservers', { state: 'ok', message: 'All HA servers are running' } )
  end
end

def report_total_failure
  send_event('pvecluster', { state: 'critical', message: "KVM cluster unreachable" } )
  send_event('corosync', { state: 'critical', message: "KVM cluster unreachable"} )
  send_event('rgmanager', { state: 'critical', message: "KVM cluster unreachable" } )
  send_event('haservers', { state: 'critical', message: "KVM cluster unreachable" })
end

def bad_nodes_report(conf)
  rows = []
  unless conf['bad_nodes'].empty?
    conf['bad_nodes'].each do |name, reason|
      rows << {"cols"=> [{"value" => name} ,{"value" => reason }] }
    end
  end
  rows
end

def extract_ticket(response)
  data = JSON.parse(response.body)
  ticket = data['data']['ticket']
  csrf_prevention_token = data['data']['CSRFPreventionToken']
  unless ticket.nil?
    token = 'PVEAuthCookie=' + ticket.gsub!(/:/, '%3A').gsub!(/=/, '%3D')
  end
  @connection_status = 'connected'
  {
    CSRFPreventionToken: csrf_prevention_token,
    cookie: token
  }
end

def create_ticket(cluster,site)
  post_param = { username: cluster['username'], realm: cluster['realm'], password: cluster['password'] }
  begin
    site['access/ticket'].post post_param do |response, request, result, &block|
      if response.code == 200
        extract_ticket response
      else
        @connection_status = 'error'
      end
    end
  rescue Exception
    @connection_status
  end
end

conf=get_config()
SCHEDULER.every '20s' do
  conf.each_key do |key|
    cluster = key
    classify_nodes(conf,cluster)
    report_total_failure if conf['good_nodes'].empty?
    hostname = conf['good_nodes'].shuffle.first
    uri = "https://#{hostname}:#{conf['port']}/api2/json/"
    site = RestClient::Resource.new(uri, :verify_ssl => false)
    auth_params = create_ticket(conf,site)
    #populate data from random good node
    rows = []
    conf['good_nodes'].each do |node|
      shortnodename = node.split('.')[0]
      rows << {"cols"=> [{"value" => shortnodename} ,{"value" => get_node_kernel(shortnodename,site,auth_params)}] }
    end
    conf['bad_nodes'].each do |k, v|
      shortnodename = k.split('.')[0]
      rows << {"cols"=> [{"value" => shortnodename} ,{"value" => v }] }
    end
    send_event('hosts_and_kernels', { rows: rows } )
    # Checking cluster status
    report_cluster_status(site,auth_params)
  end
end
