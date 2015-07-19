import btcTaint

class Bunch(object):
  def __init__(self, adict):
    self.__dict__.update(adict)

sourceAddr = ["3AbJWYLKPGMpjazqwF14gRr89cEZEdPB1P","3Hpx6FbqXfPXa19DpiGYEZvPMkM5PTfRTD","3LxZoq4zge34EVuwKZacHuUUMuU3Md2ZXA", "35BiWiw94fdyNhrTXS4MF6CGMiykpRhQSo"]
args = {}

#crea una rete di taint (reversed) integrata a partire dagli indirizzi specificati

g = btcTaint.gexf.Gexf("Ivan Di Pietro aka subzero","Taint analysis graph")
graph=g.addGraph("directed","static","Case study Satoshi Dice: reversed taint network")
#argomenti comuni
argsDict = {'depth':4, 'reverse':True, 'graph':True, 'wait':20, 'receivingBTCAddr':"3AbJWYLKPGMpjazqwF14gRr89cEZEdPB1P"} #indirizzo di destinazione non rilevante
for addr in sourceAddr:
	argsDict['sendingBTCAddr']=addr
	btcTaint.taintGraph(Bunch(argsDict), graph, 4)
output_file=open("CS_satoshiDice_depth4.gexf","wb")
g.write(output_file)