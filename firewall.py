from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *

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
    ports = open('root/pox/ext/banned-domains.txt', 'r')
    domains = open('root/pox/ext/banned-ports.txt', 'r')
    strings = open('root/pox/ext/monitored-strings.txt', 'r')
    
    self.ports = []
    self.domains = []
    self.strings = {}
    
    for line in ports:
        self.ports.append(line)
    for line in domains:
        self.domains.append(line)
    for line in strings:
        line = line.split(':')
        self.strings[line[0]] = line[1]
        
    ports.close()
    domains.close()
    strings.close()
    
    self.counts = open('root/pox/ext/counts.csv', 'w')
    self.counts.flush()
    log.debug("Firewall initialized.")

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
    event.action.forward = True

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    pass
    
  def _handle_MonitorData (self, event, packet, reverse):
      #packet.payload.payload.payload
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    pass
