from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import *
import re

# Get a logger
log = core.getLogger("fw")

class Firewall (object):
  """
  Firewall class.
  Extend this to implement some firewall functionality.
  Don't change the name or anything -- the eecore component
  expects it to be firewall.Firewall.
  """
  
  TIMEOUT = 30
  
  def __init__(self):
    """
    Constructor.
    Put your initialization code here.
    """
        #flush counts file
    #read input files
    ports = open('/root/pox/ext/banned-ports.txt', 'r')
    domains = open('/root/pox/ext/banned-domains.txt', 'r')
    strings = open('/root/pox/ext/monitored-strings.txt', 'r')
    
    self.banned_ports = set([])
    self.banned_domains = set([])
    self.monitor_strings = {}
    
    #dictionary to hold all the monitoring data for the connections
    #K: csv of: ext.IP, external port, internal IP, internal port
    #V: Timer
    self.timers = {}
    
    self.outBuffer = {}
    self.inBuffer = {}
    
    #dictionary that holds 
    #K: csv of: ext.IP, external port, internal IP, internal port, search string
    #V: counts
    self.counts = {}
    
    #set that contains valid connections as csv of ext.IP, external port, internal ip, internal port
    self.monitored_connections = set([])
    
    for line in ports:
        self.banned_ports.add(int(line))
    for line in domains:
        self.banned_domains.add(line.strip())
        
    for line in strings:
        line = line.strip()
        line = line.split(':')
        try:
            self.monitor_strings[line[0].strip()].append(line[1].strip())
        except KeyError:
            self.monitor_strings[line[0].strip()] = []
            self.monitor_strings[line[0].strip()].append(line[1].strip())
        
    ports.close()
    domains.close()
    strings.close()
    
    self.countsFile = open('/root/pox/ext/counts.txt', 'w')
    self.countsFile.flush()
    log.debug("Firewall initialized.")

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    
    # Banned port
    if flow.dstport in self.banned_ports:
        log.debug("DENIED (banned port) connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.deny = True 
        return
    
    # Defer connection
    if self.banned_domains:
        #log.debug("DEFERRED connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.defer = True
    else:
        #mark for monitoring if applicable
        self.mark_monitored(event, flow, False)
        
        event.action.forward = True
        log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )

    
  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    log.debug("HANDLING DEFERRED CONNECTION: [" +  str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
    #log.debug("Payload: " + packet.payload.payload.payload)
    payload = packet.payload.payload.payload
    
    # No need to worry about empty payload.  
    # Parse the payload for domain check
    
    host = "WHAT THE FUDGE"
    for line in payload.splitlines():
        if line.split(" ")[0] == "Host:":
            host = line.split(" ")[1]
    #log.debug("HOST: " + host)
    
    denied = False
    for banned_domain in self.banned_domains:
        domain = banned_domain.replace(".", "\.")
        domain_regex = "^" + domain + "$" + "|" + "\." + domain + "$"
        port_regex = "^" + domain + ":[0-9]{1,5}$" + "|" + "\." + domain + ":[0-9]{1,5}$"
        domain_regex = domain_regex + "|" + port_regex   
        #log.debug("domain_regex: " + domain_regex)
        denied = re.search(domain_regex, host) or denied
        
    if denied:
        event.action.deny = True
        log.debug("BOOM SHAKLA")
        log.debug("DROPPED " + host)
        log.debug("BOOM")
    else:
        # At this point, no reason to drop it.
        
        #mark for monitoring if applicable
        self.mark_monitored(event, flow, True)
        
        event.action.forward = True
        if flow.dst in self.monitor_strings.keys() :
            event.action.monitor_forward = True
            event.action.monitor_backward = True    
        
    
    
  def _handle_MonitorData (self, event, packet, reverse):
    ip = packet.payload
    tcp = ip.payload
    data = tcp.payload
    monitoredIPs = self.monitor_strings.keys()
    
    if(ip.dstip.toStr() in monitoredIPs):
        IPStr = ip.dstip.toStr() + ',' + str(tcp.dstport) + ',' + ip.srcip.toStr() + ',' + str(tcp.srcport)
        monitoredIP = ip.dstip.toStr()
    elif(ip.srcip.toStr() in monitoredIPs):
        IPStr = ip.srcip.toStr() + ',' + str(tcp.srcport) + ',' + ip.dstip.toStr() + ',' + str(tcp.dstport)
        monitoredIP = ip.srcip.toStr();
    
    #if: still in monitored connections, do:
    if IPStr in self.monitored_connections:
        #reset timer
        timer = self.timers[IPStr]
        if timer != None:
            timer.cancel()
        #must do the deletion of timer manually    
        del(self.timers[IPStr])
        self.timers[IPStr] = Timer(self.TIMEOUT, self.handle_timeout, args = [IPStr])
        
        #Loop through each string we are looking for
        size = len(data)
        for searchString in self.monitor_strings[monitoredIP]:
            cxn_string_key = IPStr + ',' + searchString
            if reverse:
                snippet = self.inBuffer[cxn_string_key]
            else:
                snippet = self.outBuffer[cxn_string_key]

            combination = snippet + data
            combosize = size + len(snippet)
            
            #count the number of times the string appears, minus the times it appears in old buffer alone
            if(combosize < len(searchString)):
                end_index = 0
            else:
                counts = len(re.findall(searchString, combination))
                if counts == 0:
                    end_index = combosize-len(searchString)
                else:
                    self.counts[cxn_string_key] = self.counts[cxn_string_key] + counts
                    last = None
                    for match in re.finditer(searchString, combination):
                        last = match
                    end_index = last.end(0)
                    
            if reverse:
                self.inBuffer[cxn_string_key] = combination[end_index:combosize]
            else:
                self.outBuffer[cxn_string_key] = combination[end_index:combosize]  
            
    else:
        log.debug("Dropped packet because connection was timedout: " + IPStr)
        
  def handle_timeout(self, IPStr):
    #output count data
    #remove connection from monitoring
    log.debug("Connection timeout: " + IPStr)
    if IPStr in self.monitored_connections:
        self.monitored_connections.remove(IPStr)
        split = IPStr.split(",")
        for string in self.monitor_strings[split[0]]:
            self.countsFile.write(split[0] + ',' + split[1] + ',' + string + ',' + str(self.counts[IPStr+ ',' + string]) + '\n')
            self.countsFile.flush()
            del(self.counts[IPStr + ',' + string])
            del(self.outBuffer[IPStr + ',' + string])
            del(self.inBuffer[IPStr + ',' + string])    
        del(self.timers[IPStr])
    
  def mark_monitored(self, event, flow, deferred):
    # Mark to monitor data
    monitoredIPs = self.monitor_strings.keys()
    if flow.src.toStr() in monitoredIPs or flow.dst.toStr() in monitoredIPs:
        if flow.src.toStr() in monitoredIPs :
            IPStr = flow.src.toStr() + ',' + str(flow.srcport) + ',' + flow.dst.toStr() + ',' + str(flow.dstport)
            monitoredIP = flow.src.toStr()
        elif flow.dst.toStr() in monitoredIPs:
            IPStr = flow.dst.toStr() + ',' + str(flow.dstport) + ',' + flow.src.toStr() + ',' + str(flow.srcport)
            monitoredIP = flow.dst.toStr()
        
        log.debug("Monitoring connection: " + IPStr)
        #Same conneciton already exists!
        if IPStr in self.monitored_connections:
            if(self.timers[IPStr] != None):
                self.timers[IPStr].cancel()
            log.debug("Old connection still exists.  Writing counts to file.")
            #output counts to countsFile
            split = IPStr.split(",")
            for string in self.monitor_strings[monitoredIP]:
                self.countsFile.write(split[0] + ',' + split[1] + ',' + string + ',' + str(self.counts[IPStr+ ',' + string]) + '\n')
                self.countsFile.flush()
        else:
            self.monitored_connections.add(IPStr)
        #new tuple to hold data snippets and timer
        if deferred:
            data = Timer(self.TIMEOUT, self.handle_timeout, args = [IPStr])
        self.timers[IPStr] = data
        
        #set up blank counts for each string
        for string in self.monitor_strings[monitoredIP]:
            self.outBuffer[IPStr + ',' + string] = ""
            self.inBuffer[IPStr + ',' + string] = ""            
            self.counts[IPStr + ',' + string] = 0
        
        #monitor this connection in both directions
        event.action.monitor_forward = True
        event.action.monitor_backward = True
        
