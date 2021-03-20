from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from ryu.lib import hub

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.sta = {}
        self.right1
        self.dps = [] 
        self.links = 8

    def creat_global_view(self):
        switch_list = get_switch(self.topology_api_app, None)
        # self.dpids = [switch.dp.id for switch in switch_list]
        for sw in switch_list:
            dpid = sw.dp.id
            self.dps.append(sw.dp)
            if len(sw.ports) != 5:
                self.sta[dpid] = 0
            else:
                self.right1 = dpid
        
    def add_init_backflow_left(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=3)
        actions = [parser.OFPActionOutput(1)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1024, instructions=inst)
        datapath.send_msg(mod)
        print(datapath.id,'added',mod)

    def add_init_flow_left(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table 0
        match = parser.OFPMatch(eth_type=0x0800, ip_dscp=10)
        inst = [parser.OFPInstructionMeter(meter_id=1), parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=256, instructions=inst, table_id=0)
        datapath.send_msg(mod)
        print(datapath.id,'added',mod)

        #table 1
        match = parser.OFPMatch(eth_type=0x0800, ip_dscp=10)
        actions = [parser.OFPActionOutput(3)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, 
              priority=256, instructions=inst, table_id=1)
        datapath.send_msg(mod)
        print(datapath.id,'added',mod)

        match = parser.OFPMatch(eth_type=0x0800, ip_dscp=12)
        actions = [parser.OFPActionGroup(1)] # argment means group_id
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
              datapath=datapath, match=match, cookie=0,
              command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, 
              priority=256, instructions=inst, table_id=1)
        datapath.send_msg(mod)
        print(datapath.id,'added',mod)

    def add_init_backflow_right(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for i in range(1,3):
            match = parser.OFPMatch(ipv4_dst="10.0.0.%s"%i)
            p = i + i % 2 * 2
            actions = [parser.OFPActionOutput(p)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=1024, instructions=inst)
            datapath.send_msg(mod)
            print(datapath.id,'added',mod)

    def add_init_flow_right(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(ipv4_dst="10.0.0.3")
        actions = [parser.OFPActionOutput(1)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1024, instructions=inst)
        datapath.send_msg(mod)
        print(datapath.id,'added',mod)

    def add_meter(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        band = parser.OFPMeterBandDscpRemark(rate=90000, burst_size=1000, prec_level=1)
        mod = parser.OFPMeterMod(datapath, ofproto.OFPMC_ADD,
                                 ofproto.OFPMF_KBPS, 1, [band])
        datapath.send_msg(req)
        print(datapath.id,'added',mod)
        mod = parser.OFPMeterMod(datapath, ofproto.OFPMC_ADD,
                                 ofproto.OFPMF_KBPS, 2, [band])
        datapath.send_msg(req)
        print(datapath.id,'added',mod)
        band = parser.OFPMeterBandDscpRemark(rate=180000, burst_size=2000, prec_level=1)
        mod = parser.OFPMeterMod(datapath, ofproto.OFPMC_ADD,
                                 ofproto.OFPMF_KBPS, 3, [band])
        datapath.send_msg(req)
        print(datapath.id,'added',mod)

    def add_group(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        action11 = [parser.OFPActionOutput(2)]
        action12 = [parser.OFPActionOutput(3)]
	    action2 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        action3 = [parser.OFPActionSetField(ip_dscp = 10)]
	    #actions2 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]

	    bucket11 = parser.OFPBucket(weight=0, actions=action11)
        bucket12 = parser.OFPBucket(weight=0, actions=action12)
	    bucket2 = parser.OFPBucket(weight=0, actions=action2)
        bucket3 = parser.OFPBucket(weight=0, actions=action3)

	    buckets1 = [bucket11, bucket2, bucket3]
        buckets2 = [bucket12, bucket2, bucket3]

	    #group_mod_req = parser.OFPGroupMod(datapath=datapath, type_=ofproto.OFPGT_ALL, group_id=1, buckets=[bucket1, bucket2])
	    mod = parser.OFPGroupMod(datapath=datapath, 
            type_=ofproto.OFPGT_ALL, group_id=1, buckets=buckets1)
        datapath.send_msg(mod)
        print(datapath.id,'added',mod)
        mod = parser.OFPGroupMod(datapath=datapath, 
            type_=ofproto.OFPGT_ALL, group_id=2, buckets=buckets2)
        datapath.send_msg(mod)
        print(datapath.id,'added',mod)
        

    @set_ev_cls(event.EventLinkAdd)
    def make_global_view(self,ev):
        if self.links != 0:
            print(self.links)
            self.links = self.links - 1
        else:
            self.creat_global_view()
            for dp in self.dps:
                if dp.id != self.right1:
                    self.add_init_backflow_left(dp)
                    self.add_init_flow_left(dp)
                    self.add_meter(dp)
                    self.add_group(dp)
                else:
                    self.add_init_flow_right(dp)
                    self.add_init_backflow_right(dp)