import hashlib
import hmac
import struct
import unittest
try:
    from tools.read_weixin4_runtime_keys import (Candidate,MASK,MASTER_MASK,NAME_RVA,VTABLE_RVA,NAME,PROFILES,
        inspect_config,inspect_cfg_master,page1_matches,raw_candidates,verify_candidates,xor_data)
except ModuleNotFoundError:
    from read_weixin4_runtime_keys import (Candidate,MASK,MASTER_MASK,NAME_RVA,VTABLE_RVA,NAME,PROFILES,
        inspect_config,inspect_cfg_master,page1_matches,raw_candidates,verify_candidates,xor_data)


def encrypted_page(key,salt):
    page=bytearray(4096)
    page[:16]=salt
    page[16:4032]=bytes((i*11+9)&255 for i in range(4016))
    mac=hashlib.pbkdf2_hmac('sha512',key,bytes(b^0x3A for b in salt),2,32)
    page[4032:]=hmac.new(mac,page[16:4032]+struct.pack('<I',1),hashlib.sha512).digest()
    return bytes(page)


class Memory:
    def __init__(self):
        self.regions={}
    def add(self,address,data):
        self.regions[address]=bytes(data)
    def read(self,address,size):
        for base,data in self.regions.items():
            if base<=address and address+size<=base+len(data):
                return data[address-base:address-base+size]
        return None


class RuntimeProbeTests(unittest.TestCase):
    def test_raw_literal_and_hmac(self):
        key,salt=bytes(range(32)),bytes(range(32,48))
        candidate=raw_candidates(b"x'"+(key+salt).hex().encode()+b"'",'synthetic')
        self.assertEqual(len(candidate),1)
        rows,_=verify_candidates(candidate,{'message/example.db':encrypted_page(key,salt)})
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['raw_encryption_key_hex'],key.hex())
        self.assertFalse(page1_matches(encrypted_page(key,salt),b'x'*32,salt))

    def test_validated_node_cache(self):
        base=0x180000000
        pair_address=0x40000010
        obj=0x50000000
        ptr=0x60000000
        key,salt=bytes(range(32)),bytes(range(32,48))
        literal=b"x'"+(key+salt).hex().encode()+b"'"
        memory=Memory()
        node=bytearray(0x50)
        struct.pack_into('<QQ',node,0x10,base+NAME_RVA,len(NAME))
        struct.pack_into('<Q',node,0x28,obj)
        memory.add(pair_address-0x10,node)
        data=bytearray(0xA0)
        struct.pack_into('<Q',data,0,base+VTABLE_RVA)
        struct.pack_into('<QQ',data,0x90,ptr,len(literal))
        memory.add(obj,data)
        memory.add(ptr,xor_data(literal))
        candidates=inspect_config(memory.read,base,pair_address)
        self.assertEqual(len(candidates),1)
        self.assertEqual(candidates[0].material,key)
        self.assertEqual(candidates[0].salt,salt)
        data[0]^=1
        memory.add(obj,data)
        self.assertEqual(inspect_config(memory.read,base,pair_address),[])

    def test_cfg_chain_is_hypothesis_until_hmac(self):
        m=Memory()
        landmark=0x40001000
        owner,cfg,data=0x50000000,0x60000000,0x70000000
        text=bytearray(32)
        text[:13]=b'global_config'
        struct.pack_into('<QQ',text,16,13,15)
        m.add(landmark,text)
        m.add(landmark+16-0x138,struct.pack('<Q',owner))
        m.add(owner+0x68,struct.pack('<Q',cfg))
        master=bytes(range(32))
        m.add(cfg+0x2B8,struct.pack('<QQQQ',data,0,32,47))
        m.add(data,xor_data(master,MASTER_MASK))
        candidates=inspect_cfg_master(m.read,landmark)
        self.assertEqual(len(candidates),1)
        self.assertTrue(candidates[0].passphrase)
        self.assertEqual(candidates[0].material,master)
        self.assertEqual(verify_candidates(candidates,{'test':encrypted_page(b'x'*32,b's'*16)})[0],[])

    def test_passphrase_derived_only_on_request(self):
        master,salt=b'synthetic-master',b's'*16
        key=hashlib.pbkdf2_hmac('sha512',master,salt,256000,32)
        candidates=[Candidate(master,'fixture',passphrase=True)]
        pages={'fixture.db':encrypted_page(key,salt)}
        self.assertEqual(verify_candidates(candidates,pages)[0],[])
        rows,masters=verify_candidates(candidates,pages,True)
        self.assertEqual(len(rows),1)
        self.assertEqual(len(masters),1)

    def test_invalid_literal_rejected(self):
        self.assertEqual(raw_candidates(b"x'not-a-key'",'fixture'),[])

    def test_current_profile_requires_its_own_name_and_vtable(self):
        profile=next(p for p in PROFILES.values() if p['version']=='4.1.15.13')
        self.assertFalse(profile['cfg_master_supported'])
        base,pair_address,obj,ptr=0x180000000,0x40000010,0x50000000,0x60000000
        memory=Memory()
        node=bytearray(0x50)
        struct.pack_into('<QQ',node,0x10,base+profile['name_rva'],len(NAME))
        struct.pack_into('<Q',node,0x28,obj)
        memory.add(pair_address-0x10,node)
        data=bytearray(0xA0)
        struct.pack_into('<Q',data,0,base+profile['vtable_rva'])
        struct.pack_into('<QQ',data,0x90,ptr,32)
        memory.add(obj,data)
        memory.add(ptr,xor_data(bytes(range(32))))
        self.assertEqual(inspect_config(memory.read,base,pair_address),[])
        self.assertEqual(inspect_config(memory.read,base,pair_address,profile)[0].material,bytes(range(32)))


if __name__=='__main__':
    unittest.main()
