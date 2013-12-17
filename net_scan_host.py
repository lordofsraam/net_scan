class Host:
	def __init__(self, element):
		self.state = element[0].attrib['state']
		self.addr = element[1].attrib['addr']
		self.mac = "UNK"
		self.vendor = "UNK"
		if len(element) > 2 and 'addrtype' in element[2].attrib and element[2].attrib['addrtype'] == 'mac':
			self.mac = element[2].attrib['addr']
		if len(element) > 2 and 'vendor' in element[2].attrib and element[2].attrib['addrtype'] == 'mac':
			self.vendor = element[2].attrib['vendor']
		self.summary = (u'\u25FB' if self.state != 'up' else u'\u25A0') + " " + self.addr

class Port:
	def __init__(self,number,protocol,service):
		self.number = number
		self.protocol = protocol
		self.service = service

class DSHost:
	def __init__(self, element):
		ports_tag = filter(lambda c: c.tag == 'ports', element)
		self.tag = element.tag
		if len(ports_tag) > 0:
			ports_tag = ports_tag[0]
			self.ports = []
			ports = filter(lambda c: c.tag == 'port' and c[0].attrib['state'] == 'open', ports_tag)
			for p in ports:
				self.ports.append(Port(p.attrib['portid'],p.attrib['protocol'],p[1].attrib['name']))
			self.num_of_ports = len(self.ports)
		else:
			self.num_of_ports = 0
			self.ports = []
		
