require 'json'
require 'rest_client'
require 'socket'
require 'timeout'
require 'yaml'

def get_node_kernel(node,site,auth_params)
  site["nodes/#{node}/status"].get auth_params do |response, request, result, &block|
    JSON.parse(response.body)['data']['kversion'].split[1]
  end
end

def get_ha_data(site,auth_params)
  site["cluster/ha/status/current"].get auth_params do |response, request, result, &block|
    JSON.parse(response.body)['data']
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
  quorate = status[0]['quorate']
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
  config_file = File.dirname(File.expand_path(__FILE__)) + '/../../shared/proxmox_dashing/config_v0cpt3.yml'
  config = YAML::load(File.open(config_file))['config_data']
  config['bad_nodes']  = {}
  config['good_nodes'] = []
  return config
end

def classify_nodes(config)
  config['proxmox_hosts'].each do |host|
    if is_port_open?(host,config['port'])
      uri       = "https://#{host}:#{config['port']}/api2/json/"
      post_param = { username: config['username'], realm: config['realm'], password: config['password'] }
      begin
        site = RestClient::Resource.new(uri, :verify_ssl => false, open_timeout: 3)
        site['access/ticket'].post post_param do |response, request, result, &block|
          if response.code == 200
            config['bad_nodes'].delete(host) if config['bad_nodes'].include?(host)
            config['good_nodes'] << host unless config['good_nodes'].include?(host)
          else
            config['good_nodes'].delete(host) if config['good_nodes'].include?(host)
            config['bad_nodes'][host] = "cannot authenticate"
          end
        end
      rescue Exception
        config['good_nodes'].delete(host) if config['good_nodes'].include?(host)
        config['bad_nodes'][host] = "cannot authenticate"
      end
    else
      config['good_nodes'].delete(host) if config['good_nodes'].include?(host)
      config['bad_nodes'][host] = "not listening"
    end
    config
  end
end

def report_cluster_status(site,auth_params)
  cluster_status = get_data(site,auth_params)
  ha_status = get_ha_data(site,auth_params)
	nodes = []
  nodes = cluster_status.select { |a| a['type'] == 'node'}
  downhostlist = select_hosts(nodes, 'online',0)

  send_event('v0cpt3_pvecluster', { state: 'critical', message: "Cluster lost quorum!" } ) if cluster_status[0]['quorate'] != 1
  if downhostlist.empty?
    send_event('v0cpt3_pvecluster', { state: 'ok', message: 'Cluster has quorum and all hosts up' } )
  else
    send_event('v0cpt3_pvecluster', { state: 'warning', message: "Host(s) not up:\n #{downhostlist.join(", ")}"} )
  end

  unless ha_status[0]['status'] == "OK"
    send_event('v0cpt3_haservers', { state: 'critical', message: 'HA status is critical' } )
  else
    send_event('v0cpt3_haservers', { state: 'ok', message: 'All HA servers are running' } )
  end
end

def report_total_failure
  send_event('v0cpt3_pvecluster', { state: 'critical', message: "KVM cluster unreachable" } )
  send_event('v0cpt3_haservers', { state: 'critical', message: "KVM cluster unreachable" })
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

def create_ticket(config,site)
  post_param = { username: config['username'], realm: config['realm'], password: config['password'] }
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
SCHEDULER.every '5s' do
  classify_nodes(conf)
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
  send_event('v0cpt3_hosts_and_kernels', { rows: rows } )
  report_cluster_status(site,auth_params)
end
