import serial
import dexcrc16
from time import sleep

    
SOH = chr(0x01)
STX = chr(0x02)
ETX = chr(0x03)
EOT = chr(0x04)
DLE = chr(0x10)
ENQ = chr(0x05)
NAK = chr(0x15)
ETB = chr(0x17)
    
class DexReader:
    def __init__(self,serialPath):
        self.MARS_MASTER_STRING = "009252131001R01L01"
        self.MARS_SLAVE_STRING  = "9252131001SR01L01"
        self.path = serialPath
        self.ser = None
        self.content = ""
    
    def read(self):
        print "--------------------------------"
        self.openConnection()
        mode = self.getConnection()
        if mode == 0:
            print "Failed to get connection"

        if mode == 1:
            self.key = self.MARS_MASTER_STRING
            #master mode 
            if self.slaveHandshake():
                if self.masterHandshake():
                    self.exchangeData()              

        if mode == 2:   
            self.key = MARS_SLAVE_STRING   
            # slave mode
            self.masterHandshake()
            self.slaveHandshake()
            self.exchangeData()
        
        self.ser.close()
        return self.content            
            
            
    def openConnection(self):
        print "opening connection to " + self.path
        self.ser = serial.Serial(self.path, 9600, timeout=0.01)
                
    def getConnection(self):
        print "Getting connection"
        
        for i in range(0,10):
            self.ser.write(ENQ)
            sleep(0.01)
            #x = self.ser.read()
            x = self.readChar()
            if len(x) > 0:
                self.printReceivedData(x)
                for char in x:
                    if char == ENQ:
                        print "Received ENQ for init.  Connecting as master"
                        return 1
                    if char == DLE:
                        print "Received DLE for init. Connecting as slave"
                        return 2        
        return 0                

    def masterHandshake(self):
        print "Entering Master Handshake"
        
        state = 0
        retries = 5
        self.ser.flushInput()
        self.ser.write(ENQ)
        while retries > 0:
            x = self.ser.read()
            if len(x) > 0 or state == 3:
                self.printReceivedData(x)
                retries = 5
                
                if state == 0:
                    print "State 0 - waiting for command"
                    if x == DLE:
                        print "Got DLE"
                        state = 1
                    else:
                        print "Got something else. Sending ENQ"
                        self.ser.write(ENQ)
                        self.ser.flush()
                        sleep(0.1)
                elif state == 1:
                    if x == '0':
                        print "Got second half of DLE"
                        state = 3
                    else:
                        print "Something wrong"
                        self.ser.write(ENQ)
                        self.ser.flush()
                        sleep(0.1)
                        state = 0
                elif state == 3:
                    print "State 3 - Sending master key"
                    self.ser.write(DLE)
                    sleep(0.015)
                    self.ser.write(SOH)
                    sleep(0.015)
                    for char in self.key:
                        self.ser.write(char)
                        sleep(0.015)
                    self.ser.write(DLE)
                    self.ser.write(ETX)
                    crc = dexcrc16.crcStr(self.key + ETX)
                    self.ser.write(chr(crc & 0xFF))
                    self.ser.write(chr(crc >> 8))
                    state = 4
                elif state == 4:
                    print "State 4 - Waiting for confirmation"
                    if x == DLE:
                        print "Got DLE first half of confirmation"
                        state = 5
                    else:
                        print "Got something other than DLE. Bad"
                        return False
                elif state == 5:
                    if x == '0' or x == '1':
                        print "Got second half of confirmation. All good"
                        self.ser.write(EOT)
                        self.ser.flush()
                        print "End of master handshake"
                        return True
                    else:
                        print "Got something wrong. Sending NAK"
                        self.ser.write(NAK)
                        state = 0                        
            else:
                retries = retries - 1
                sleep(0.01)
        print "gave up"  
                
    def slaveHandshake(self):
        print "Entering slave handshake"
        self.ser.flushInput()
        retries = 5
        state = 0
        receivedData = ""
        while retries > 0:
            x = self.ser.read()
            if len(x) > 0:
                self.printReceivedData(x)
                retries = 5
                
                if state == 0:
                    print "State 0 - waiting for command"
                    if x == EOT:
                        print "Got EOT. Ending now"
                        return True
                    elif x == ENQ:
                        print "Got ENQ. Replying with DLE"
                        self.ser.write(DLE)
                        self.ser.write('0')
                        self.ser.flush()
                    elif x == DLE:
                        print "Got DLE. Will receive data."
                        state = 1                        
                elif state == 1:
                    print "State 1 - waiting for SOH"
                    if x == SOH:
                        print "Got SOH"
                        receivedData = ""
                        state = 2
                elif state == 2:
                    print "State 2 - receiving data"
                    if x == DLE:
                        print "Got DLE. End of data."
                        state = 3
                    else:
                        receivedData += x
                elif state == 3:
                    print "State 3 - Waiting for ETX"
                    if x == ETX:
                        print "Got ETX"
                        receivedData += x
                        state = 4
                    else:
                        print "Got something was not ETX. Resetting"
                        state = 0
                elif state == 4:
                    print "State 4 - Receiving first crc byte"
                    receivedData += x
                    state = 5
                elif state == 5:
                    print "State 5 - Receiving second crc byte"
                    receivedData += x
                    crc = dexcrc16.crcStr(receivedData)
                    print "Calculated crc=",crc
                    if crc == 0:
                        print "CRC is good. Sending DLE,1"
                        self.ser.write(DLE)
                        self.ser.write('1')
                        self.ser.flush()
                    else:
                        print "CRC failed. Sending NAK"
                        self.ser.write(NAK)
                        self.ser.flush()
                    state = 0
            else:
                retries = retries - 1
                
        print "end of slave handshake"
        
    def printReceivedData(self, data):
        print "Received data:",data,"=",data.encode('hex')
        
    def uploadblock(self,data, final):
        finalmarker = ETB
        if final:
            finalmarker = ETX

        crc = dexcrc16.crcStr(data  + finalmarker)
        print "Writing block:", data.rstrip(),"CRC=",crc
        self.ser.flushInput()
        sleep(0.01)
        self.ser.write(DLE)
        self.ser.write(STX)
        self.ser.write(data)
        self.ser.write(DLE)
        self.ser.write(finalmarker)
        
        # Write checksum
        self.ser.write(chr(crc & 0xFF))
        self.ser.write(chr(crc >> 8))
        
        receivedData = ""
        while True:
            x = self.ser.read()
            if len(x) > 0:
                self.printReceivedData(x)
                receivedData += x
                if len(receivedData) >= 2 and \
                        receivedData[-2] == DLE and \
                        (receivedData[-1] == '0' or receivedData[-1]=='1'):
                    print "received confirmation of block" 
                    return
        
    def waitForExchangeReady(self):    
        ready = False
        print "Waiting for ready signal before exchanging data" 
        self.ser.flushInput()
        sleep(0.01)
        receivedData = ""
        print "Writing ENQ"        
        self.ser.write(ENQ)
        self.ser.flush()
        while not ready:
            for i in range(0,5):
                x = self.ser.read()
                if len(x) > 0:
                    self.printReceivedData(x)
                    receivedData += x
                    if len(receivedData) >= 2 and \
                            receivedData[-2] == DLE and \
                            receivedData[-1] == '0':
                        print "Received query response"
                        ready = True
                        break
            if not ready:
                print "Not ready yet. Writing ENQ"                
                self.ser.write(ENQ)
                self.ser.flush()
          
    def readChar(self):
        retries = 5
        while retries > 0:
            x = self.ser.read()
            if len(x) > 0:
                return x
            else:
                retries = retries - 1
        return None
        
    def exchangeData(self):
        print "Exchanging data"
        
        receivedData = ""
        block = ""
        
        blockNumber = 1
        state = 0
        retries = 5
        self.ser.flushInput()
        
        while retries > 0:
            x = self.ser.read()
            if len(x) > 0:
                self.printReceivedData(x)
                retries = 5
                if state == 0:
                    print "State 0 - waiting for command"
                    if x == ENQ:
                        print "Got ENQ, replying"
                        self.ser.write(DLE)
                        sleep(0.015)
                        self.ser.write('0')
                        sleep(0.015)
                        self.ser.flush()
                    elif x == DLE:
                        print "Got DLE, start of block.."
                        state = 1
                elif state == 1:
                    print "State 1 - waiting for STX"
                    if x == STX:
                        print "Got STX"
                        state = 2
                        receivedData = ""
                        block = ""
                elif state == 2:
                    print "State 2 - receiving data"
                    if x == DLE:
                        print "Got DLE, end of data"
                        state = 3
                    else:
                        receivedData += x
                        block += x
                elif state == 3:
                    print "State 3 - waiting for end of block"
                    if x == ETB:
                        print "Got ETB, end of current block"
                        receivedData += x
                        state = 4
                    elif x == ETX:
                        print "Got ETX, end of last block"
                        receivedData += x
                        state = 6
                    else:
                        print "Got something other than end of block"
                        self.ser.write(NAK)
                        state = 0
                elif state == 4:
                    print "State 4 - Waiting for first half of CRC"
                    receivedData += x
                    state = 5
                elif state == 5:
                    print "State 5 - Waiting for second half of CRC"
                    receivedData += x
                    crc = dexcrc16.crcStr(receivedData)
                    print "Got all data, crc=",crc
                    if crc == 0:
                        print "CRC is good"
                        self.content += block
                        self.ser.write(DLE)
                        self.ser.write('0')
                        state = 0  
                    else:
                        print "CRC failed"
                        self.ser.write(NAK)
                        state = 0 
                elif state == 6:
                    print "State 6 - Waiting for first half of CRC"
                    receivedData += x
                    state = 7
                elif state == 7:
                    print "State 7 - Waiting for second half of CRC"
                    receivedData += x
                    crc = dexcrc16.crcStr(receivedData)
                    print "Got all data, crc=",crc
                    if crc == 0:
                        print "CRC is good"
                        self.content += block
                        self.ser.write(DLE)
                        self.ser.write('0')
                        state = 8   
                    else:
                        print "CRC failed"
                        self.ser.write(NAK)
                        state = 0 
                elif state == 8:
                    print "State 8 - waiting for EOT"
                    if x == EOT:
                        print "Got EOT, End of data exchange"
                        return True
                    else:
                        print "Got something else."
                        self.ser.write(NAK)
                        state = 0
            else:
                retries = retries-1
        print "Gave up"
        return False    
        
reader = DexReader("/dev/ttyp3")
print "===DEX DATA:"
print reader.read()
print "=== end of data"