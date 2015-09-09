require 'rest_client'
require 'json'

set :kvm_rows, []

def check_response(response)
  if response.code == 200
    JSON.parse(response.body)['data']
  else
    'NOK: error code = ' + response.code.to_s
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

def create_ticket
  post_param = { username: @username, realm: @realm, password: @password }
  @site['access/ticket'].post post_param do |response, request, result, &block|
    if response.code == 200
      extract_ticket response
    else
      @connection_status = 'error'
    end
  end
end

def get_node_status(node)
	@site["nodes/#{node}/status"].get @auth_params do |response, request, result, &block|
		return check_response(response)
	end
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

def list_norgmanager(nodes)
    bad_rgmanager_nodes_array = nodes.select { |a| a['rgmanager'] == 1 }
    p bad
    bad_rgmanager_nodes = bad_rgmanager_nodes_array.map { |x| x["name"] } 
    norgmanager = @bad_rgmanager_nodes.join("\n")
end

host      = 'kvm0v3.jnb1.host-h.net'
uri       = "https://#{host}:8006/api2/json/"
@username = 'proxmoxdasher'
@password = 'secret'
@realm    = 'pve'
@connection_status = ''
@status   = {}

@site = RestClient::Resource.new(uri, :verify_ssl => false)
@auth_params = create_ticket

SCHEDULER.every '2s' do

	@site["cluster/status"].get @auth_params do |response, request, result, &block|
	  @status = check_response(response)
	end
	@nodes = []
	@bad_rgmanager_nodes = []

	if @status.class == Array
    if have_quorum(@status)
      send_event('quorate', { status: 'OK', message: 'Cluster has quorum', status:'OK' } )
    else
      send_event('quorate', { status: 'CRITICAL', message: 'Cluster lost quorum', status:'Critical' } )
    end
      
    nodes = @status.select { |a| a['type'] == 'node'}
    norgmanagerlist = list_norgmanager(nodes)
    unless norgmanagerlist.empty?
	  	send_event('rgmanager', { status: 'CRITICAL', message: "Node(s) not running RG Manager: \n #{norgmanagerlist}" } )
	  else
		  send_event('rgmanager', { status: 'OK', message: 'RGmanager is healthy' } )
	  end
  end
  @ha_hosts = @nodes.select { |a| a['type'] == 'group'}
	@nodes.each do | node |
    p node.inspect
			status = "OFFLINE"
  end
end
