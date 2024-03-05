def updateIdentity():
    leaf = bin(0xf)[2:] + bin(int('202271789') & 0xfffffff)[2:]
    return int(leaf,2)

print(updateIdentity())