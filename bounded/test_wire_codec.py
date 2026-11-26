"""Reference-format checks, not production conformance or formal verification."""
import copy, json, unittest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import wire_codec as w

class WireTests(unittest.TestCase):
    def setUp(self): self.rk,self.ck,self.p,self.token,self.r,self.tag,self.q,self.state=w.fixtures(); self.nonces=set()
    def check(self,q=None,signature=None,token='default',state=None,now=100000):
        q=self.q if q is None else q
        signature=w.sign(self.p,q) if signature is None else signature
        return w.validate(q,signature,self.r,self.tag,self.rk,self.ck,self.p.public_key(),self.state if state is None else state,now,self.nonces,self.token if token=='default' else token)
    def test_real_hmac_ed25519_success(self): self.assertEqual(self.check(),w.fingerprint(self.q))
    def test_changed_field_invalidates_signature(self):
        sig=w.sign(self.p,self.q); q={**self.q,'operation_id':'different'}
        with self.assertRaises(InvalidSignature): self.check(q,sig)
    def test_wrong_receipt_key_purpose(self):
        with self.assertRaises(ValueError): w.receipt_tag({**self.rk,'purpose':'token-commitment'},self.r)
    def test_wrong_commitment_key_purpose(self):
        with self.assertRaises(ValueError): w.commitment({**self.ck,'purpose':'receipt-authentication'},self.r,self.token)
    def test_wrong_receipt_authentication_key(self):
        self.rk={**self.rk,'secret':bytes(32)}
        with self.assertRaises(ValueError): self.check()
    def test_foreign_token_even_with_fresh_valid_proof(self):
        q={**self.q,'token_sha256':w.sha(b'foreign')}
        with self.assertRaises(ValueError): self.check(q,token=b'foreign')
    def test_different_approved_policy_rejected(self):
        r=copy.deepcopy(self.r); r['authority']=[['repo-B','write','branch','main']]
        self.state={**self.state,'approved_receipt':r}
        with self.assertRaises(ValueError): self.check()
    def test_unbound_signing_key_rejected(self):
        p=Ed25519PrivateKey.from_private_bytes(bytes(32))
        with self.assertRaises(ValueError): w.validate(self.q,w.sign(p,self.q),self.r,self.tag,self.rk,self.ck,p.public_key(),self.state,100000,set(),self.token)
    def test_cross_domain_mac_separation(self):
        fields=[('value','b')]; obj={'value':b'test'}
        a=w.mac(self.rk,'receipt-authentication','DOMAIN-A',fields,obj)
        b=w.mac(self.rk,'receipt-authentication','DOMAIN-B',fields,obj)
        self.assertNotEqual(a,b)
    def test_receipt_changed_field_invalidates_mac(self):
        changed={**self.r,'client':'different-client'}
        self.assertNotEqual(w.receipt_tag(self.rk,changed),self.tag)
    def test_future_timestamp_replay_window(self):
        q={**self.q,'signed_at_ms':160000}
        self.check(q,now=100000)
        with self.assertRaises(ValueError): self.check(q,now=219999)
        # No pruning is implemented: the ledger retains it even after expiry.
        self.assertEqual(len(self.nonces),1)
    def test_extra_or_missing_fields_rejected(self):
        with self.assertRaises(ValueError): w.request_bytes({**self.q,'ignored':0})
        q=dict(self.q); del q['root']
        with self.assertRaises(ValueError): w.request_bytes(q)
    def test_bad_base64(self):
        for x in ['YQ==','YQ+','YQ/','YQ\n','YR','a']:
            with self.subTest(x=x), self.assertRaises(ValueError): w.unb64(x)
    def test_tuple_framing_not_concatenation(self):
        f=[('a','s'),('b','s')]
        self.assertNotEqual(w.encode('TEST',f,{'a':'ab','b':'c'}),w.encode('TEST',f,{'a':'a','b':'bc'}))
    def test_unicode_and_uint_policy(self):
        for x in ['e\u0301','bad\x00id','bad\u202eid']:
            with self.assertRaises(ValueError): w.text(x)
        self.assertEqual(w.text('é'),'é'.encode())
        for x in [-1,2**64,True,1.0]:
            with self.assertRaises(ValueError): w.uint(x)
    def test_authority_sort_duplicate_and_url_rejection(self):
        a=['repo-A','read','diff','D']; b=['repo-B','read','diff','D']
        self.assertEqual(w.authority([a,b]),w.authority([b,a]))
        for rows in [[a,a],[['https://host/a','read','diff','D']],[['repo-A','read','diff','d%2f']]]:
            with self.assertRaises(ValueError): w.authority(rows)
    def test_exact_method_route(self):
        for q in [{**self.q,'method':'post'},{**self.q,'route':w.ROUTES['issue']+'/'},{**self.q,'route':'https://host'+w.ROUTES['issue']}]:
            with self.assertRaises(ValueError): w.request_bytes(q)
    def test_clock_and_replay(self):
        with self.assertRaises(ValueError): self.check(now=160001)
        self.check()
        with self.assertRaises(ValueError): self.check()
    def ready(self):
        return {**self.state,'phase':'READY','generation':4,'operation_id':self.q['operation_id'],'fingerprint':w.fingerprint(self.q),'response_sha256':w.sha(b'DUMMY-sealed-response'),'next_receipt_sha256':w.sha(b'DUMMY-next-receipt'),'ready_until_ms':180000}
    def retry(self,kind='retrieve'):
        q={**self.q,'kind':kind,'route':w.ROUTES[kind],'signed_at_ms':100001,'nonce':bytes(range(128,160))}
        if kind=='ack': q.update(response_sha256=self.ready()['response_sha256'],next_receipt_sha256=self.ready()['next_receipt_sha256'])
        return q
    def test_fresh_retry_same_fingerprint(self):
        q=self.retry(); self.assertEqual(w.fingerprint(q),w.fingerprint(self.q)); self.assertNotEqual(w.request_bytes(q),w.request_bytes(self.q))
        self.assertEqual(self.check(q,token=None,state=self.ready(),now=100001),w.fingerprint(self.q))
    def test_ack_binds_exact_response(self):
        q=self.retry('ack'); self.check(q,token=None,state=self.ready(),now=100001)
        q={**q,'nonce':bytes(32),'response_sha256':w.sha(b'wrong')}
        with self.assertRaises(ValueError): self.check(q,token=None,state=self.ready(),now=100001)
    def test_retry_context_phase_expiration_and_closure(self):
        for state in [{**self.ready(),'phase':'CLOSED'},{**self.ready(),'phase':'RECOVERY_REQUIRED'},{**self.ready(),'phase':'REFRESHING'},{**self.ready(),'fingerprint':bytes(32)},{**self.ready(),'epoch':3},{**self.ready(),'ready_until_ms':100000}]:
            with self.subTest(state=state['phase']),self.assertRaises(ValueError): self.check(self.retry(),token=None,state=state,now=100001)
    def test_old_generation_cannot_issue(self):
        with self.assertRaises(ValueError): self.check(state=self.ready())
    def test_duplicate_json_and_extra_envelope(self):
        with self.assertRaises(ValueError): w.parse_request_json('{"request":{},"request":{},"signature":"","token":null}')
        with self.assertRaises(ValueError): w.parse_request_json('{"request":{},"signature":"","token":null,"extra":1}')
    def test_child_handle_mac_and_action_signature(self):
        key,p,handle,tag,action=w.action_fixture()
        self.assertEqual(len(tag),32)
        p.public_key().verify(p.sign(w.action_bytes(action)),w.action_bytes(action))
        changed={**action,'authority':[['repo-B','write','branch','main']]}
        with self.assertRaises(InvalidSignature): p.public_key().verify(p.sign(w.action_bytes(action)),w.action_bytes(changed))
        with self.assertRaises(ValueError): w.handle_tag({**key,'purpose':'receipt-authentication'},handle)
        self.assertNotEqual(tag,w.handle_tag(key,{**handle,'epoch':3}))
    def test_child_action_rejects_extra_fields_and_multiple_operations(self):
        _,_,_,_,a=w.action_fixture()
        with self.assertRaises(ValueError): w.action_bytes({**a,'extra':True})
        with self.assertRaises(ValueError): w.action_bytes({**a,'authority':a['authority']*2})
    def test_vectors_are_reproducible(self):
        from pathlib import Path
        v=json.loads(Path(__file__).with_name('wire-vectors.json').read_text())
        self.assertEqual(v['receipt_payload_hex'],w.receipt_bytes(self.r).hex())
        self.assertEqual(v['receipt_tag'],w.b64(self.tag))
        self.assertEqual(v['signature'],w.b64(w.sign(self.p,self.q)))
        _,p,_,_,a=w.action_fixture()
        self.assertEqual(v['child_action']['signature'],w.b64(p.sign(w.action_bytes(a))))
        q,s,t=w.parse_request_json(json.dumps({'request':v['request'],'signature':v['signature'],'token':v['token']}))
        self.assertEqual(self.check(q,s,token=t),w.fingerprint(self.q))
if __name__=='__main__': unittest.main()
