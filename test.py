import DexReader

reader = DexReader.DexReader("/dev/ttyp3")

data = reader.read()
print "===DEX DATA:"
print data
print "=== end of data"