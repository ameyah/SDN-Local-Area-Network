from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology.event import EventSwitchEnter, EventSwitchLeave
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from topology import load_topology
import networkx as nx

# This function takes as input a networkx graph. It then computes
# the minimum Spanning Tree, and returns it, as a networkx graph.
def compute_spanning_tree(G):

    # The Spanning Tree of G
    covered_nodes = []
    to_be_explored = [G.nodes()[0]]
    while to_be_explored:
	current_node = to_be_explored.pop(0)
	if current_node not in covered_nodes:
		covered_nodes.append(current_node)
		to_be_explored.extend(G[current_node].keys())
	
    active_node = None
    ST = {}
    print covered_nodes
    for node in covered_nodes:
	ST[node] = []
    active_node_pointer = 0
    ctive_node = covered_nodes[active_node_pointer]
    for node in covered_nodes:
	if active_node is None:
		active_node = node
		continue
	if node in G[active_node]:
		ST[active_node].append(node)
		ST[node].append(active_node)
	else:
		while node not in G[active_node]:
			active_node_pointer += 1
			active_node = covered_nodes[active_node_pointer]
		ST[active_node].append(node)
		ST[node].append(active_node)

    print ST
    return ST


class L2Forwarding(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(L2Forwarding, self).__init__(*args, **kwargs)

        # Load the topology
        topo_file = 'topology.txt'
        self.G = load_topology(topo_file)

        # For each node in the graph, add an attribute mac-to-port
        for n in self.G.nodes():
            self.G.add_node(n, mactoport={})

        # Compute a Spanning Tree for the graph G
        self.ST = compute_spanning_tree(self.G)

	self.mac_port_map = {}
	self.count = 1

        print self.get_str_topo(self.G)
        # print self.get_str_topo(self.ST)

    # This method returns a string that describes a graph (nodes and edges, with
    # their attributes). You do not need to modify this method.
    def get_str_topo(self, graph):
        res = 'Nodes\tneighbors:port_id\n'

        att = nx.get_node_attributes(graph, 'ports')
        for n in graph.nodes_iter():
            res += str(n)+'\t'+str(att[n])+'\n'

        res += 'Edges:\tfrom->to\n'
        for f in graph:
            totmp = []
            for t in graph[f]:
                totmp.append(t)
            res += str(f)+' -> '+str(totmp)+'\n'

        return res

    def return_st_neighbor_ports(self, datapath_id):
	port_info = nx.get_node_attributes(self.G, 'ports')
	neighbors = self.ST[datapath_id]
	neighbors = [str(neighbor) for neighbor in neighbors]
	return [port_info[datapath_id][neighbor] for neighbor in port_info[datapath_id] if neighbor == 'host' or neighbor in neighbors]

    # This method returns a string that describes the Mac-to-Port table of a
    # switch in the graph. You do not need to modify this method.
    def get_str_mactoport(self, graph, dpid):
        res = 'MAC-To-Port table of the switch '+str(dpid)+'\n'

        for mac_addr, outport in graph.node[dpid]['mactoport'].items():
            res += str(mac_addr)+' -> '+str(outport)+'\n'

        return res.rstrip('\n')

    def add_flow_mod(self, datapath, in_port, destination_mac, out_port):
	of_protocol = datapath.ofproto
	parser = datapath.ofproto_parser
	actions = [parser.OFPActionOutput(out_port)]
	match = parser.OFPMatch(in_port=in_port, dl_dst=haddr_to_bin(destination_mac))
	#instructions = [parser.OFPInstructionActions(of_protocol.OFPIT_APPLY_ACTIONS, actions)]
	flow_mod_msg = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0, command=of_protocol.OFPFC_ADD, 
		idle_timeout=0, hard_timeout=0, priority=of_protocol.OFP_DEFAULT_PRIORITY, flags=of_protocol.OFPFF_SEND_FLOW_REM, actions=actions)
	datapath.send_msg(flow_mod_msg)

    @set_ev_cls(EventSwitchEnter)
    def _ev_switch_enter_handler(self, ev):
        print('enter: %s' % ev)

    @set_ev_cls(EventSwitchLeave)
    def _ev_switch_leave_handler(self, ev):
        print('leave: %s' % ev)

    # This method is called every time an OF_PacketIn message is received by 
    # the switch. Here we must calculate the best action to take and install
    # a new entry on the switch's forwarding table if necessary
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        message = event.msg
        datapath = message.datapath
        of_protocol = datapath.ofproto
        of_protocol_parser = datapath.ofproto_parser
	packet_info = packet.Packet(message.data)
	ethernet_info = packet_info.get_protocol(ethernet.ethernet)

	destination_mac = ethernet_info.dst
        source_mac = ethernet_info.src

     	datapath_id = datapath.id
	self.mac_port_map.setdefault(datapath_id, {})
	#print "dpid " + str(dpid) + "src: " + str(src) + "dest: " + str(dst)
	
	self.mac_port_map[datapath_id][source_mac] = message.in_port
	map_found_flag = False
	if destination_mac in self.mac_port_map[datapath_id]:
		out_port = self.mac_port_map[datapath_id][destination_mac]
		map_found_flag = True
	print self.count
	self.count += 1

	packet_data = None
	if message.buffer_id == of_protocol.OFP_NO_BUFFER:
		packet_data = message.data

	if map_found_flag:
		self.add_flow_mod(datapath, message.in_port, destination_mac, out_port)
		actions = [of_protocol_parser.OFPActionOutput(out_port)]
	# print self.mac_port_map

	#if destination_mac in self.mac_port_map[host_id]:
	#	actions = [of_protocol_parser.OFPActionOutput(self.mac_port_map[host_id][destination_mac])]
	#else:
	#	#print [out_port for out_port in self.return_st_neighbor_ports(host_id)]
	#	actions = []
	#	for out_port in self.return_st_neighbor_ports(host_id):
	#		actions.append(of_protocol_parser.OFPActionOutput(out_port))

	#if out_port != ofproto.OFPP_FLOOD:
        #        self.add_flow_mod(dp, msg.in_port, dst, actions)
	
	#actions = [of_protocol_parser.OFPActionOutput(of_protocol.OFPP_FLOOD)]
	else:
		actions = [of_protocol_parser.OFPActionOutput(out_port) for out_port in self.return_st_neighbor_ports(datapath_id)]
        message_out = of_protocol_parser.OFPPacketOut(
            datapath=datapath, buffer_id=message.buffer_id, in_port=message.in_port,
            actions=actions, data=packet_data)
        datapath.send_msg(message_out)

