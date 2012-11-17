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
    #V: list that holds:
    #    0: input data snippet
    #    1: output data snippet
    #    2: Timer
    self.monitored_data = {}
    
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
        
    self.length = 0
    for line in strings:
        line = line.strip()
        if len(line) > self.length:
            self.length = len(line)
        line = line.split(':')
        try:
            self.monitor_strings[line[0].strip()].append(line[1].strip())
        except KeyError:
            self.monitor_strings[line[0].strip()] = []
            self.monitor_strings[line[0].strip()].append(line[1].strip())
        
    ports.close()
    domains.close()
    strings.close()
    
    # You need to write to file EACH TIME MONITORED CONNECTION CLOSES(read spec)
    # Use open('/root/pox/ext/counts.csv', 'a') for APPENDING.  
    self.countsFile = open('/root/pox/ext/counts.csv', 'w')
    self.countsFile.flush()
    self.countsFile.close()
    log.debug("Firewall initialized.")

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    
    # Banned port?
    if flow.dstport in self.banned_ports:
        log.debug("DENIED (banned port) connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.deny = True 
        return
    
    # Defer connection?
    #TODO: handle monitor/deferred case!!
    if self.banned_domains:
        #log.debug("DEFERRED connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.defer = True
    else:
        #mark for monitoring if applicable
        self.mark_monitored(event, flow)
        
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
        self.mark_monitored(event, flow)
        
        event.action.forward = True
        if flow.dst in self.monitor_strings.keys() :
            event.action.monitor_forward = True
            event.action.monitor_backward = True    
        
    
    
  def _handle_MonitorData (self, event, packet, reverse):
    ip = packet.payload
    tcp = ip.payload
    #is this a string? call payload again?
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
        timer = self.monitored_data[IPStr].timer
        if timer != None:
            timer.cancel()
        #must do the deletion of timer manually    
        del(self.monitored_data[IPStr].timer)
        self.monitored_data[IPStr].timer = Timer(self.TIMEOUT, self.handle_timeout, args = [IPStr])
        
        #retrieve buffer for this particular connection and direction
        if reverse:
            snippet = self.monitored_data[IPStr].inBuff
        else:
            snippet = self.monitored_data[IPStr].outBuff
        
        #Loop through each string we are looking for
        size = len(data)
        combination = snippet + data
        combosize = size + len(snippet)
        
        for searchString in self.monitor_strings[monitoredIP]:
            #count the number of times the string appears, minus the times it appears in old buffer alone
            counts = len(re.findall(searchString, combination)) - len(re.findall(searchString, snippet))
            self.counts[IPStr + ',' + searchString] = self.counts[IPStr + ',' + searchString] + counts;
    
        #Now set up the next buffer
        #packet is bigger than largest search word
        if(combosize > self.length):
            snippet = combination[combosize-self.length:combosize]
        #search word is bigger than packet + buffer
        else:
            snippet = combination
        
        #overwrite old buffer with new one  
        if reverse:
            self.monitored_data[IPStr].inBuff = snippet
        else:
            self.monitored_data[IPStr].outBuff = snippet
    else:
        log.debug("WARNING: Tried to monitor connection that isn't in internal set")
        
  def handle_timeout(self, IPStr):
    #output count data
    #remove connection from monitoring
    log.debug("Connection timeout: " + IPStr)
    self.countsFile = open('/root/pox/ext/counts.csv', 'a')
    self.monitored_connections.remove(IPStr)
    split = IPStr.split(",")
    for string in self.monitor_strings[split[0]]:
        self.countsFile.write(split[0] + ',' + split[1] + ',' + string + ',' + str(self.counts[IPStr+ ',' + string]) + '\n')
        del(self.counts[IPStr + ',' + string])
    self.countsFile.close()
    del(self.monitored_data[IPStr].timer)
    del(self.monitored_data[IPStr])
    
  def mark_monitored(self, event, flow):
    # Mark to monitor data
    monitoredIPs = self.monitor_strings.keys()
    #log.debug("Flow source: " + flow.src.toStr() + " Flow dest: " + flow.dst.toStr())
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
            log.debug("Old connection still exists.  Writing counts to file.")
            #output counts to countsFile
            IPStr = IPStr.split(",")
            self.countsFile.open('/root/pox/ext/counts.csv', 'a')
            for string in self.monitor_strings[monitoredIP]:
                #TODO: get rid of old connection somehow??
                self.countsFile.write(IPStr[0] + ',' + IPStr[1] + ',' +string + ',' + str(self.counts[IPStr + "," + string]) + "\n")
            self.countsFile.close()
        else:
            self.monitored_connections.add(IPStr)
        #new tuple to hold data snippets and timer
        data = monitor_tuple(IPStr)
        data.timer = Timer(self.TIMEOUT, self.handle_timeout, args = [IPStr])
        self.monitored_data[IPStr] = data
        
        #set up blank counts for each string
        for string in self.monitor_strings[monitoredIP]:
            self.counts[IPStr + ',' + string] = 0
        
        #monitor this connection in both directions
        event.action.monitor_forward = True
        event.action.monitor_backward = True
        
class monitor_tuple:
    def __init__(self, IPStr):
        self.inBuff = ""
        self.outBuff = ""
        self.timer = None
        
