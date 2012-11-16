from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
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
    
    self.banned_ports = []
    self.banned_domains = []
    self.monitor_strings = {}
    
    for line in ports:
        self.banned_ports.append(int(line))
        
    for line in domains:
        self.banned_domains.append(line.strip())
        
    for line in strings:
        line = line.strip().split(':')
        self.monitor_strings[line[0]] = line[1]
        
    ports.close()
    domains.close()
    strings.close()
    
    # Don't write a blank file yet
    #self.counts = open('/root/pox/ext/counts.csv', 'w')
    #self.counts.flush()
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
    if self.banned_domains:
        #log.debug("DEFERRED connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.defer = True
    else:
        event.action.forward = True
        log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
    
    # Mark to monitor data?
    if flow.src in self.monitor_strings.keys() :
        event.action.monitor_forward = True
    
    if flow.dst in self.monitor_strings.keys() :
        event.action.monitor_backward = True
    # What about the case self to self?

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    log.debug("HANDLING DEFERRED CONNECTION: [" +  str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
    log.debug("Payload: " + packet.payload.payload.payload)
    payload = packet.payload.payload.payload
    
    # No need to worry about empty payload.  
    # Parse the payload for domain check
    
    host = "WHAT THE FUDGE"
    for line in payload.splitlines():
        if line.split(" ")[0] == "Host:":
            host = line.split(" ")[1]
    log.debug("HOST: " + host)
    
    for banned_domain in self.banned_domains:
        domain = banned_domain.replace(".", "\.")
        domain_regex = "^" + domain + "$" + "|" + "\." + domain + "$"
        port_regex = "^" + domain + ":[0-9]{1,5}$" + "|" + "\." + domain + ":[0-9]{1,5}$"
        domain_regex = domain_regex + port_regex   
        log.debug("domain_regex: " + domain_regex)
        if re.search(domain_regex, host):
            event.action.forward = False
            log.debug("BOOM SHAKLA")
            log.debug("DROPPED " + host + " with regex: " + domain_regex)
            log.debug("BOOM")
            return
        
    # At this point, no reason to drop it.
    event.action.forward = True
    
  
  def _handle_MonitorData (self, event, packet, reverse):
      #packet.payload.payload.payload
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    pass
