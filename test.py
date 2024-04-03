# def updateIdentity():
#     leaf = bin(0xf)[2:] + bin(int('202271789') & 0xfffffff)[2:]
#     return int(leaf,2)

# print(updateIdentity())
import p4runtime_sh.shell as sh

def setTableEntry(tableName, matchFields, actionName, actionParams):
    te = sh.TableEntry(tableName)(action=actionName)
    for field, value in matchFields.items():
        te.match[field] = value
    for param, value in actionParams.items():
        te.action[param] = value
    te.insert()
    #return te

def main():
    sh.setup(
        device_id=1,
        grpc_addr='localhost:50001',
        election_id=(0, 1),
        config=sh.FwdPipeConfig('p4src/build/p4info.txt', 'p4src/build/bmv2.json')
    )
    
    geoMatchFields = {
        'hdr.gbc.geoAreaPosLat': '1',
        'hdr.gbc.geoAreaPosLon': '1',
        'hdr.gbc.disa': '1',
        'hdr.gbc.disb': '1'
    }
    geoActionParams = {
        'dst_port': '1'
    }
    setTableEntry('IngressPipeImpl.routing_geo_table', geoMatchFields, 'IngressPipeImpl.geo_ucast_route', geoActionParams)
    # te = sh.TableEntry('IngressPipeImpl.routing_geo_table')(action='IngressPipeImpl.geo_ucast_route')
    # te.match['hdr.gbc.geoAreaPosLat'] = '1'
    # te.match['hdr.gbc.geoAreaPosLon'] = '1'
    # te.match['hdr.gbc.disa'] = '1'
    # te.match['hdr.gbc.disb'] = '1'
    # te.action['dst_port'] = '1'
    # te.insert()
    sh.TableEntry('IngressPipeImpl.routing_geo_table').read(lambda te: print(te))
    idMatchFields = {
        'hdr.id.dstIdentity': '20227001'
    }
    idActionParams = {
        'dst_port': '1'
    }
    setTableEntry('IngressPipeImpl.routing_id_table', idMatchFields, 'IngressPipeImpl.set_next_id_hop', idActionParams)
    sh.TableEntry('IngressPipeImpl.routing_id_table').read(lambda te: print(te))
    mfMatchFields = {
        'hdr.mf.dest_guid': '1'
    }
    mfActionParams = {
        'dst_port': '1'
    }
    setTableEntry('IngressPipeImpl.routing_mf_table', mfMatchFields, 'IngressPipeImpl.set_next_mf_hop', mfActionParams)
    sh.TableEntry('IngressPipeImpl.routing_mf_table').read(lambda te: print(te))
    sh.teardown()
if __name__ == '__main__':
    main()