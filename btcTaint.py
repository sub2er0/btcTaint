#script realizzato per Python 3.2

import urllib.request
import re
import string
import argparse
import operator
import time
from bs4 import BeautifulSoup
from bs4 import SoupStrainer
import gexf

BLOCKCHAINTAINT_BASE_URL = "https://blockchain.info/taint/"
TEST_BTC_ADDRESS = "1dice6GV5Rz2iaifPvX7RMjfhaNPC8SXH"
BTC_ADDR_REGEX = "^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$"
trace = []
args = {}
# static proxy configuration
#proxies = {'http':'http://127.0.0.1:3128'}
#proxyHandler= urllib.request.ProxyHandler(proxies)


tableParsingFilter = SoupStrainer('tbody') #parsing limited to table only

class taintRecord:
	def __init__(self, branchColorCode, branchNum, taintPercentage, count):
		self.branchNum = branchNum
		self.branchColorCode = branchColorCode
		self.taintPercentage = float(taintPercentage[:-1])
		self.count = count
		
	def __repr__(self):
		return 'Branch Color Code: {} | Branch #: {} | Taint %: {} | Count: {}'.format(self.branchColorCode, self.branchNum, self.taintPercentage, self.count)
		
	def __lt__(self, other):
		return self.taintPercentage < other

	def ___le__(self, other):
		return self.taintPercentage <= other

	def __eq__(self, other):
		return self.taintPercentage == other

	def __ne__(self, other):
		return self.taintPercentage != other

	def __gt__(self, other):
		return self.taintPercentage > other

	def __ge__(self, other):
		return self.taintPercentage >= other

def parseTaintTable(sourceAddr, targetAddr, shift="", wait=3, reverse=False):
	parsedTable=[]
	
	urlToOpen=BLOCKCHAINTAINT_BASE_URL + targetAddr
	if (reverse):
		urlToOpen=BLOCKCHAINTAINT_BASE_URL + sourceAddr + "?reversed=true"
	print (shift+urlToOpen, end="")
	time.sleep(wait) #delay to avoid HTTP 429
	r = urllib.request.urlopen(urlToOpen)
	#r = open('taintTest.html')
	soup = BeautifulSoup(r.read(), "lxml", parse_only=tableParsingFilter)
	#print (soup.div)

	for tabrow in soup.find_all('tr'):
		rowItems=[]
		for tdata in tabrow.children:
			tdataStr = repr(tdata).replace('<td>', '').replace('</td>', '').replace('\n','').strip()
			if (tdata != '\n'):
				#print (tdataStr)
				rowItems.append(tdataStr)
		parsedTable.append(rowItems)
	return parsedTable

def parseBranch(htmlCode):
	branchSoup = BeautifulSoup(htmlCode, "lxml")
	branchDivs=branchSoup("div")
	if len(branchDivs) == 1:
		return (branchDivs[0]['style'][-7:-1],"NA")
	return (branchDivs[0]['style'][-7:-1],branchDivs[1].string)
	
def parseBtcAddress(htmlCode):
	addrSoup = BeautifulSoup(htmlCode, "lxml")
	return addrSoup.a.string
	
def parseGenericText(htmlCode):
	textSoup = BeautifulSoup(htmlCode, "lxml")
	return textSoup.string
	
def  BTCAddress(v):
	if (re.match(BTC_ADDR_REGEX, v)):
		return v
	raise argparse.ArgumentTypeError("String '%s' is not a valid BTC Address"%(v,))
	
def hex_to_rgb(value):
	#value = value.lstrip('#')
	lv = len(value)
	return tuple(int(value[i:i+int(lv/3)], 16) for i in range(0, lv, int(lv/3)))
	
def analyzeTaint(sourceAddr, targetAddr, reverse=False, depth=1, MAX_DEPTH=-1, verbose=False, wait=3):	
	
	if depth == 1:
		if not reverse:
			trace.insert(depth,(targetAddr, {})) #trace initialization
		else:
			trace.insert(MAX_DEPTH,(sourceAddr, {})) #trace initialization
		
	parsedTable = parseTaintTable(sourceAddr, targetAddr, shift='   '*(depth-1), wait=wait, reverse=reverse)
	print()
	
	taintRegistry = {}
	for row in parsedTable:
		#print (row)
		
		record=taintRecord(parseBranch(row[0])[0], parseBranch(row[0])[1], parseGenericText(row[2]), parseGenericText(row[3]))
		
		#record = {}
		#record['branch'] = parseBranch(row[0] )
		#record['taintPercentage']=parseGenericText(row[2])
		#record['count'] =  parseGenericText(row[3])
		taintRegistry[parseBtcAddress(row[1])] = record
	sortedTR = sorted(taintRegistry.items(), key=operator.itemgetter(1), reverse=True)
	#if args.verbose:
	#for r in sortedTR:
	#	print (r)
				
	if verbose:
		print ('Searching at level ' + str(depth)+'...', end='')
	
	#print (taintRegistry.keys())
	address = sourceAddr #default case (no reverse)
	if reverse:
		address = targetAddr
	
	#print ("Check: " + address + " in " + str(taintRegistry.keys()))
	if address in taintRegistry.keys(): #hit: exit condition
		
		if verbose:
			print ('Hit at level ' + str(depth))
		
		trace.append((address, taintRegistry[address]))
		return True
	print ('no match')
	
	#print (str(depth+1) + " " + str(MAX_DEPTH))
	if depth+1 > MAX_DEPTH: #depth limit reached: exit condition
		#print ('Depth limit exceeded: exiting')
		return False	
	
	if verbose:
		print ('Going deeper (level ' + str(depth+1) + ')')
	
	trace.insert(depth+1,()) #init next element
	for r in sortedTR: #recursive call
		nextAddr=r[0]
		
		trace[depth] = r #temporary insert: to be confirmed if hit found
		
		if (reverse):
			nextSource = nextAddr   #forward search
			nextTarget = targetAddr #same target

		else:
			nextSource = sourceAddr	#same source
			nextTarget = nextAddr	#backward search
		
		if verbose:
			print ('   '*(depth) + "[DEPTH "+ str(depth+1) + "]  Trying " + nextSource + "-->" + nextTarget, end = "")
			if reverse:
				print(" (reverse taint)")
			else:
				print()
		if analyzeTaint(nextSource, nextTarget, reverse, depth+1, MAX_DEPTH, verbose, wait):
			return True
		
def printTrace(trace, args):
	step = 1
	print ("\n##### TAINT TRACE ####")
	if (args.reverse):
		for item in trace:
			if (step==len(trace)):
				print ("T   "+repr(item))
			else:	
				print (str(step)+"   "+repr(item))
			step = step + 1
	else:
		while len(trace) > 1:
			item = trace.pop()
			print (str(step)+"   "+repr(item))
			step = step + 1
		print ("T   "+trace.pop()[0])

def taintGraph(args, graph, depth=1):
	print("  "*(args.depth-depth) +"[DEPTH " + str(args.depth-depth+1)+"] - Taint network: "  , end="")
	#parse taint table
	address = args.sendingBTCAddr
	if (args.reverse):
		address = args.receivingBTCAddr
	parsedTable = parseTaintTable(address, address, shift="  "*(args.depth-depth), wait=args.wait, reverse=args.reverse)
	
	if not graph.nodeExists(address):
		graph.addNode(address,address)	#add the BTC address
	#add connected nodes
	print ("  Nodes found: " + str(len(parsedTable)))
	for row in parsedTable:
		record=taintRecord(parseBranch(row[0])[0], parseBranch(row[0])[1], parseGenericText(row[2]), parseGenericText(row[3]))
		nodeColor = hex_to_rgb(record.branchColorCode)
		nextAddr = parseBtcAddress(row[1])
		####version with custom size
		nodeSize=10.0
		if record.branchNum != "NA":
			nodeSize=float(record.branchNum)*10.0
		if not graph.nodeExists(nextAddr):
			graph.addNode(nextAddr,nextAddr, r="{0:d}".format(nodeColor[0]), g="{0:d}".format(nodeColor[1]), b="{0:d}".format(nodeColor[2]), size="{0:.1f}".format(nodeSize))
			#graph.addNode(nextAddr,nextAddr, r="{0:d}".format(nodeColor[0]), g="{0:d}".format(nodeColor[1]), b="{0:d}".format(nodeColor[2]))
			
		if args.reverse:
			graph.addEdge(address+"#"+nextAddr, address, nextAddr, weight=record.taintPercentage)
		else:
			graph.addEdge(nextAddr+"#"+address, nextAddr, address, weight=record.taintPercentage)
		
		#recursive call
		if (depth-1 > 0):	
			args.receivingBTCAddr=nextAddr
			args.sendingingBTCAddr=nextAddr
			taintGraph(args, graph, depth-1)
	

	
	
def main():
	# program arguments setup
	argparser = argparse.ArgumentParser(description='Taint analysis between Bitcoin addresses')
	argparser.add_argument('sendingBTCAddr',help='Source Bitcoin address', type=BTCAddress)
	argparser.add_argument('receivingBTCAddr', help='Destination Bitcoin address', type=BTCAddress)
	argparser.add_argument("-r", "--reverse", help="Reverse tain analysis (forward analysis)", action="store_true")
	argparser.add_argument("-d", "--depth", type=int, default=1, help="Max length of indirect link between addresses (default 1 = direct link)")
	argparser.add_argument("-v", "--verbose", help="Show parsing details", action="store_true")
	argparser.add_argument("-w", "--wait", help="Delay in seconds between URL requests", type=int, default=3)
	argparser.add_argument("-g", "--graph", help="Export taint graph in GEXF format to the specified file. This command is alternative to standard analysis and only requires the destination address and a depth.", type=str)
	args = argparser.parse_args()
	if (args.graph):	#graph mode
		print ("\n###### Generating taint graph ######") 
		if args.reverse:
			print ("Forward (reversed) taint - sending address: " + args.sendingBTCAddr)
		else:
			print ("Backward taint - Receiving address: " + args.receivingBTCAddr)
		print ("Depth: " + str(args.depth))
		print ("Saving GEXF graph to file: " + args.graph)
		print()
		#init graph
		g = gexf.Gexf("Ivan Di Pietro aka subzero","Taint analysis graph")
		if args.reverse:
			graph=g.addGraph("directed","static","Taint reversed network for BTC address: " + args.sendingBTCAddr)
		else:
			graph=g.addGraph("directed","static","Taint network for BTC address: " + args.receivingBTCAddr)
		taintGraph(args, graph, args.depth)
		#save graph to file
		output_file=open(args.graph,"wb")
		g.write(output_file)
	else:	#standard taint analysis
		if analyzeTaint(args.sendingBTCAddr, args.receivingBTCAddr, args.reverse, 1, args.depth, args.verbose, args.wait):
			printTrace(trace, args)
		
	
if __name__ == "__main__":
    main()



	