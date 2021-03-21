# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.ofproto import ether
from ryu.lib.packet import ipv4

# for shell command
import subprocess
import time

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    aggregation_counter=0

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        #match = parser.OFPMatch()
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        #                                  ofproto.OFPCML_NO_BUFFER)]
        #self.add_flow(datapath, 0, match, actions)

        ##################################################################
        # kokokara                                                       #
        ##################################################################

        # add rule for metering in s1

	self.logger.info(ev.msg.datapath.id)

        if ev.msg.datapath.id==1:
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

	    ######################
	    # Create Meter Table #
	    ######################


            #bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, len_=0, rate=100, burst_size=10)]
	    bands = [parser.OFPMeterBandDscpRemark(rate=90000, burst_size=10, prec_level=1)]
            req=parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=1, bands=bands)
            datapath.send_msg(req)

            req=parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=2, bands=bands)
            datapath.send_msg(req)
	    
	    # for aggregation
            bands = [parser.OFPMeterBandDscpRemark(rate=180000, burst_size=10, prec_level=1)]
            req=parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=3, bands=bands)
            datapath.send_msg(req)

	    ####################
	    # Create new table #
	    ####################

	    make_table_req = parser.OFPTableMod(datapath, 1, 3)
	    datapath.send_msg(make_table_req)

	    make_table_req = parser.OFPTableMod(datapath, 2, 3)
	    datapath.send_msg(make_table_req)


	    ######################
	    # Create Group Table #
	    ######################

	    action1 = [parser.OFPActionOutput(3)]
	    action2 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
	    #actions2 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]

	    bucket1 = parser.OFPBucket(weight=0, actions=action1)
	    bucket2 = parser.OFPBucket(weight=0, actions=action2)

	    buckets = [bucket1, bucket2]

	    #group_mod_req = parser.OFPGroupMod(datapath=datapath, type_=ofproto.OFPGT_ALL, group_id=1, buckets=[bucket1, bucket2])
	    group_mod_req = parser.OFPGroupMod(datapath=datapath, type_=ofproto.OFPGT_ALL, group_id=1, buckets=buckets)
            datapath.send_msg(group_mod_req)


	
	    ###########
	    # Table 0 #
	    ###########

	    # for goto table
            match = parser.OFPMatch(in_port=1)
            #actions = [parser.OFPActionOutput(1)]
            #inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionMeter(1,ofproto.OFPIT_METER)]
	    #inst = [parser.OFPInstructionMeter(1,ofproto.OFPIT_METER), parser.OFPInstructionGotoTable(1)]
	    inst = [parser.OFPInstructionMeter(meter_id=1), parser.OFPInstructionGotoTable(1)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst, table_id=0)
            datapath.send_msg(mod)

	    """
	    # for throughput test
            match = parser.OFPMatch(in_port=1)
            actions = [parser.OFPActionOutput(3)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=5, instructions=inst, table_id=0)
            datapath.send_msg(mod)
	    """

	    # for ARP
            match = parser.OFPMatch(eth_type=0x0806, in_port=1)
            actions = [parser.OFPActionOutput(2)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=6, instructions=inst, table_id=0)
            datapath.send_msg(mod)

	    # for reply message from h2
            match = parser.OFPMatch(in_port=2)
            actions = [parser.OFPActionOutput(1)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst, table_id=0)
            datapath.send_msg(mod)

	    # for h3
	    match = parser.OFPMatch(in_port=3)
            inst = []
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst, table_id=0)
            datapath.send_msg(mod)

	    ###########
	    # Table 1 #
	    ###########

	    # include meter 1
            match = parser.OFPMatch(eth_type=0x0800, ip_dscp=10)
            actions = [parser.OFPActionOutput(2)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst, table_id=1)
            datapath.send_msg(mod)

	    # Over meter 1
            match = parser.OFPMatch(eth_type=0x0800, ip_dscp=12)
            #match = parser.OFPMatch(ip_proto=4, ip_dscp=0x1a)
	    inst = [parser.OFPInstructionMeter(meter_id=2), parser.OFPInstructionGotoTable(2)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst, table_id=1)
            datapath.send_msg(mod)

	    ###########
	    # Table 2 #
	    ###########

	    # include meter 2
            match = parser.OFPMatch(eth_type=0x0800, ip_dscp=12)
            actions = [parser.OFPActionOutput(3)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst, table_id=2)
            datapath.send_msg(mod)

	    # Over meter 2


            match = parser.OFPMatch(eth_type=0x0800, ip_dscp=14)
            #actions = [ofproto.OFPP_CONTROLLER]
            #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
	    actions = [parser.OFPActionGroup(1)] # argment means group_id
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=15,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst, table_id=2)
            datapath.send_msg(mod)

	    """
	    # Emergency Entry
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(2)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=0, instructions=inst, table_id=1)
            datapath.send_msg(mod)
	    """

	    subprocess.Popen('tc qdisc add dev s1-eth2 root tbf rate 100mbit burst 5000kb limit 100kb', shell=True)
	    subprocess.Popen('tc qdisc add dev s1-eth3 root tbf rate 100mbit burst 5000kb limit 100kb', shell=True)
	    subprocess.Popen('tc qdisc add dev s3-eth3 root tbf rate 100mbit burst 5000kb limit 100kb', shell=True)
	    #subprocess.Popen('tc qdisc add dev s2-eth1 root tbf rate 1000mbit burst 10000kb limit 10kb', shell=True)

	    self.logger.info('tc command')

        if ev.msg.datapath.id==2:
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

	    # for ARP
            match = parser.OFPMatch(eth_type=0x0806, in_port=2)
            actions = [parser.OFPActionOutput(1)]
	    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst)
            datapath.send_msg(mod)

	    """
	    # for packets marked 4
            match = parser.OFPMatch(eth_type=0x0800, ip_dscp=0x04, eth_src='00:00:00:00:00:01')
            actions = [parser.OFPActionOutput(1)]
	    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=5, instructions=inst)
            datapath.send_msg(mod)

	    # for packets marked 6 from s3
            match = parser.OFPMatch(eth_type=0x0800, ip_dscp=0x06, eth_src='00:00:00:00:00:01')
            actions = [parser.OFPActionOutput(1)]
	    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=5, instructions=inst)
            datapath.send_msg(mod)

	    """

            match = parser.OFPMatch(eth_type=0x0800, in_port=2)
            actions = [parser.OFPActionSetField(ip_dscp=1), parser.OFPActionOutput(1)]
	    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=5, instructions=inst)
            datapath.send_msg(mod)


            match = parser.OFPMatch(in_port=1)
            actions = [parser.OFPActionOutput(2)]
	    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst)
            datapath.send_msg(mod)

            match = parser.OFPMatch(eth_type=0x0800, in_port=3)
            actions = [parser.OFPActionSetField(ip_dscp=2), parser.OFPActionOutput(1)]
	    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst)
            datapath.send_msg(mod)



        if ev.msg.datapath.id==3:
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser


            match = parser.OFPMatch(in_port=2)
            actions = [parser.OFPActionOutput(3)]
	    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst)
            datapath.send_msg(mod)

            match = parser.OFPMatch(in_port=3)
            actions = [parser.OFPActionOutput(2)]
	    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst)
            datapath.send_msg(mod)

            match = parser.OFPMatch(in_port=1)
	    inst = []
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=3, instructions=inst)
            datapath.send_msg(mod)





            #kokomade


	    #self.logger.info("detapath, ofproto, parser = %s %s %s ", datapath, ofproto, parser)
	    
	
	###################
	#		  #
	#  original code  #
	#		  #
	###################

	# print data

	#self.logger.info("Print data !")
	#self.logger.info(datapath)
	#self.logger.info(ofproto)
	#self.logger.info(parser)
	#self.logger.info(ev.msg.datapath.id)
	#self.logger.info("Print data end !")


	# koko de syoki Flow Table wo tukuru

	# zettai HIT sinai table sakusei

	# tekitou na hit sinai mono
	#match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="1.2.3.4", ipv4_dst="9.8.7.6")
	#actions = [parser.OFPActionOutput(2)]

	# metadata 
	#meta_value = 184
	#meta_mask = 0xffffffff

	#instruction
	#inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionWriteMetadata(meta_value, meta_mask)]

	# mod sakusei
	#mod = datapath.ofproto_parser.OFPFlowMod(
	#	datapath=datapath, match=match, cookie=0,
	#	command=ofproto.OFPFC_ADD, idle_timeout=0,  
	#	hard_timeout=0, priority=3, instructions=inst, table_id=1)

	#datapath.send_msg(mod)

	#self.logger.info("Create new flow table!")



	###################
	#		  #
	#  original code  #
	#		  #
	###################




    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
	parser = dp.ofproto_parser

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

	self.logger.info('OFPFlowRemoved received: '
              'cookie=%d priority=%d reason=%s table_id=%d '
              'duration_sec=%d duration_nsec=%d '
              'idle_timeout=%d hard_timeout=%d '
              'packet_count=%d byte_count=%d match.fields=%s',
              msg.cookie, msg.priority, reason, msg.table_id,
              msg.duration_sec, msg.duration_nsec,
              msg.idle_timeout, msg.hard_timeout,
              msg.packet_count, msg.byte_count, msg.match)

	if msg.cookie == 20:

	    self.logger.info('\nStart flow entry delete process')
	    self.logger.info('ev.msg.datapath.id=%d\n', ev.msg.datapath.id)

	    subprocess.Popen('tc qdisc change dev s1-eth2 root tbf rate 100mbit burst 5000kb limit 100kb', shell=True)
	    subprocess.Popen('tc qdisc change dev s1-eth3 root tbf rate 100mbit burst 5000kb limit 100kb', shell=True)
	    subprocess.Popen('tc qdisc change dev s3-eth3 root tbf rate 100mbit burst 5000kb limit 100kb', shell=True)

            match = parser.OFPMatch(eth_src='00:00:00:00:00:01')
            mod = dp.ofproto_parser.OFPFlowMod(
              datapath=dp, match=match, cookie=10, command=ofp.OFPFC_DELETE_STRICT, priority=10, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY)
            dp.send_msg(mod)
	    
	    #global aggregation_counter
	    SimpleSwitch13.aggregation_counter = 0


	# out_port=ofp.OFPP_ANY,

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]


        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)


	# Add aggregation method
	ipv4_header = pkt.get_protocol(ipv4.ipv4)

	#if ev.msg.datapath.id==1 and ipv4_header.tos == 56:
	#global aggregation_counter
	if ev.msg.datapath.id==1 and SimpleSwitch13.aggregation_counter==0 :

	    self.logger.info("\nCookie in PacketIn Message is %d ", ev.msg.cookie)

	    # for goto table
            match = parser.OFPMatch(eth_src='00:00:00:00:00:01')
	    inst = [parser.OFPInstructionMeter(meter_id=3), parser.OFPInstructionGotoTable(1)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=10,
              command=ofproto.OFPFC_ADD, idle_timeout=0,  
              hard_timeout=0, priority=10, instructions=inst, table_id=0, flags=ofproto.OFPFF_SEND_FLOW_REM)
            datapath.send_msg(mod)

	    # Over meter 3
            match = parser.OFPMatch(eth_type=0x0800, ip_dscp=12)
            actions = [parser.OFPActionOutput(2)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=20,
              command=ofproto.OFPFC_ADD, idle_timeout=10,  
              hard_timeout=0, priority=10, instructions=inst, table_id=1, flags=ofproto.OFPFF_SEND_FLOW_REM)
            datapath.send_msg(mod)

	    #time.sleep(0.5)

	    subprocess.Popen('sleep 0.5; tc qdisc change dev s1-eth2 root tbf rate 1000mbit burst 50000kb limit 1000kb', shell=True)
	    subprocess.Popen('sleep 0.5; tc qdisc change dev s1-eth3 root tbf rate 1000mbit burst 50000kb limit 1000kb', shell=True)
	    subprocess.Popen('sleep 0.5; tc qdisc change dev s3-eth3 root tbf rate 1000mbit burst 50000kb limit 1000kb', shell=True)


	    """
	    match = parser.OFPMatch(eth_src='00:00:00:00:00:01')
            actions = [parser.OFPActionOutput(2)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=10,
              command=ofproto.OFPFC_ADD, idle_timeout=10,  
              hard_timeout=0, priority=10, instructions=inst, table_id=0, flags=ofproto.OFPFF_SEND_FLOW_REM)
            datapath.send_msg(mod)

	    match = parser.OFPMatch(eth_src='00:00:00:00:00:01')
            actions = [parser.OFPActionOutput(2)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=20,
              command=ofproto.OFPFC_ADD, idle_timeout=10,  
              hard_timeout=0, priority=10, instructions=inst, table_id=2, flags=ofproto.OFPFF_SEND_FLOW_REM)
            datapath.send_msg(mod)
	    """
	    """
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
	    """


	    self.logger.info("Aggregation method completed!")
	    SimpleSwitch13.aggregation_counter = 1
	    
	    return




        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
