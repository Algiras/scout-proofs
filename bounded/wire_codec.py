"""Executable proposed PACT wire reference; NOT the shipped PACT protocol."""
import base64, hashlib, hmac, re, struct, unicodedata
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

U64_MAX = 2**64 - 1
RECEIPT_FIELDS = [('receipt_key_id','s'),('commitment_key_id','s'),('root','s'),('consent','s'),('principal','s'),('session','s'),('capability','s'),('provider','s'),('client','s'),('enc_key_sha256','b'),('sign_key_sha256','b'),('authority','a'),('refreshable','o'),('deadline_ms','u'),('epoch','u'),('generation','u'),('commitment','b')]
HANDLE_FIELDS = [('handle_key_id','s'),('issuer','s'),('delegation','s'),('root','s'),('session','s'),('parent','s'),('child','s'),('child_key_sha256','b'),('supervisor','s'),('provider','s'),('client','s'),('authority','a'),('expiry_ms','u'),('budget','u'),('epoch','u')]
ACTION_FIELDS = [('method','s'),('route','s'),('authority_id','s'),('delegation','s'),('root','s'),('session','s'),('parent','s'),('child','s'),('epoch','u'),('handle_sha256','b'),('provider','s'),('client','s'),('authority','a'),('signed_at_ms','u'),('nonce','b')]
COMMON = [('authority_id','s'),('root','s'),('session','s'),('generation','u'),('epoch','u'),('receipt_sha256','b'),('token_sha256','b'),('operation_id','s')]
ROUTES = {'issue':'/pact-reference/v1/renew/issue','retrieve':'/pact-reference/v1/renew/retrieve','ack':'/pact-reference/v1/renew/ack'}
REQUEST_FIELDS = [('kind','s'),('method','s'),('route','s')] + COMMON + [('response_sha256','b'),('next_receipt_sha256','b'),('signed_at_ms','u'),('nonce','b')]

def sha(b): return hashlib.sha256(b).digest()
def text(s):
    if not isinstance(s,str) or not s or unicodedata.normalize('NFC',s)!=s or any(unicodedata.category(c).startswith('C') for c in s): raise ValueError('noncanonical string')
    b=s.encode('utf-8')
    if len(b)>4096: raise ValueError('string too long')
    return b

def lp(b):
    if len(b)>1048576: raise ValueError('field too long')
    return struct.pack('>I',len(b))+b

def uint(n):
    if type(n) is not int or not 0<=n<=U64_MAX: raise ValueError('uint64')
    return struct.pack('>Q',n)

def authority(rows):
    """Exact ASCII opaque (resource, operation, argument-name, argument-value) tuples."""
    if not isinstance(rows,list) or not rows or len(rows)>1024: raise ValueError('authority')
    encoded=[]
    for row in rows:
        if not isinstance(row,(list,tuple)) or len(row)!=4: raise ValueError('authority tuple')
        if any(not isinstance(x,str) or not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,256}',x) for x in row): raise ValueError('opaque ASCII authority')
        encoded.append(b''.join(lp(text(x)) for x in row))
    if len(set(encoded))!=len(encoded): raise ValueError('duplicate authority')
    return struct.pack('>I',len(encoded))+b''.join(lp(x) for x in sorted(encoded))

def encode(domain, fields, obj):
    if type(obj) is not dict or set(obj)!={k for k,_ in fields}: raise ValueError('missing/extra fields')
    out=b'PACTREF\x01'+lp(domain.encode('ascii'))+struct.pack('>I',len(fields))
    for name,typ in fields:
        v=obj[name]
        if typ=='s': b=text(v)
        elif typ=='u': b=uint(v)
        elif typ=='o':
            if type(v) is not bool: raise ValueError('boolean')
            b=bytes([int(v)])
        elif typ=='a': b=authority(v)
        elif typ=='b':
            if type(v) is not bytes: raise ValueError('bytes')
            b=v
        else: raise ValueError('type')
        out+=lp(name.encode('ascii'))+typ.encode('ascii')+lp(b)
    return out

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')
def unb64(s):
    if type(s) is not str or not re.fullmatch('[A-Za-z0-9_-]*',s): raise ValueError('base64url')
    try: b=base64.b64decode(s+'='*((-len(s))%4),altchars=b'-_',validate=True)
    except Exception as e: raise ValueError('base64url') from e
    if b64(b)!=s: raise ValueError('noncanonical base64url')
    return b

def mac(key,purpose,domain,fields,obj):
    if key['purpose']!=purpose or len(key['secret'])!=32: raise ValueError('wrong key purpose')
    return hmac.new(key['secret'],encode(domain,fields,obj),hashlib.sha256).digest()

def commitment(key, r, token):
    fields=[('key_id','s'),('root','s'),('provider','s'),('client','s'),('generation','u'),('token','b')]
    obj=dict(key_id=r['commitment_key_id'],root=r['root'],provider=r['provider'],client=r['client'],generation=r['generation'],token=token)
    if key['id']!=obj['key_id'] or not token or len(token)>16384: raise ValueError('commitment key/token')
    return mac(key,'token-commitment','PACT-TOKEN-COMMITMENT-v1',fields,obj)

def receipt_bytes(r):
    for f in ('enc_key_sha256','sign_key_sha256','commitment'):
        if len(r[f])!=32: raise ValueError('receipt digest size')
    return encode('PACT-RECEIPT-v1',RECEIPT_FIELDS,r)

def receipt_tag(key,r):
    receipt_bytes(r)
    if key['id']!=r['receipt_key_id']: raise ValueError('receipt key id')
    return mac(key,'receipt-authentication','PACT-RECEIPT-v1',RECEIPT_FIELDS,r)

def receipt_digest(r,tag): return sha(receipt_bytes(r)+lp(tag))
def request_bytes(q):
    if q['kind'] not in ROUTES or q['method']!='POST' or q['route']!=ROUTES[q['kind']]: raise ValueError('method/route/kind')
    for f in ('receipt_sha256','token_sha256','response_sha256','next_receipt_sha256'):
        if type(q[f]) is not bytes or len(q[f])!=32: raise ValueError('digest size')
    if type(q['nonce']) is not bytes or len(q['nonce'])!=32: raise ValueError('nonce size')
    if q['kind']!='ack' and (q['response_sha256']!=bytes(32) or q['next_receipt_sha256']!=bytes(32)): raise ValueError('unexpected acknowledgement fields')
    return encode('PACT-RENEWAL-PROOF-v1',REQUEST_FIELDS,q)

def fingerprint(q): return sha(encode('PACT-RENEWAL-OPERATION-v1',COMMON,{k:q[k] for k,_ in COMMON}))
def sign(private,q): return private.sign(request_bytes(q))

def validate(q, signature, r, tag, receipt_key, commitment_key, public, state, now_ms, nonce_book, token=None):
    """Checks only: caller MUST hold linearizable state/nonce transaction through reservation."""
    raw=request_bytes(q)
    if sha(public.public_bytes_raw())!=state['sign_key_sha256']: raise ValueError('unbound public key')
    public.verify(signature,raw)  # no authoritative mutation or provider action before auth
    uint(now_ms)
    if abs(now_ms-q['signed_at_ms'])>60000: raise ValueError('clock window')
    replay=(state['sign_key_sha256'],q['nonce'])
    if replay in nonce_book: raise ValueError('nonce replay')
    if not hmac.compare_digest(receipt_tag(receipt_key,r),tag): raise ValueError('receipt authentication')
    if receipt_digest(r,tag)!=q['receipt_sha256']: raise ValueError('receipt digest')
    for f in ('root','session','epoch'):
        if q[f]!=r[f] or q[f]!=state[f]: raise ValueError('record context')
    if q['authority_id']!=state['authority_id'] or r['sign_key_sha256']!=state['sign_key_sha256']: raise ValueError('authority/key binding')
    if receipt_bytes(r)!=receipt_bytes(state['approved_receipt']): raise ValueError('approved receipt mismatch')
    if not r['refreshable'] or now_ms>=r['deadline_ms'] or state['phase'] in ('CLOSED','RECOVERY_REQUIRED'): raise ValueError('closed/deadline')
    if q['generation']!=r['generation']: raise ValueError('request generation')
    fp=fingerprint(q)
    if q['kind']=='issue':
        if state['phase']!='RENEWAL_ACTIVE' or state['generation']!=q['generation']: raise ValueError('issue phase')
        if token is None or sha(token)!=q['token_sha256'] or not hmac.compare_digest(commitment(commitment_key,r,token),r['commitment']): raise ValueError('token substitution')
    else:
        if now_ms>=state['ready_until_ms']: raise ValueError('response retention expired')
        if state['phase']!='READY' or state['generation']!=q['generation']+1 or state['operation_id']!=q['operation_id'] or state['fingerprint']!=fp: raise ValueError('retry mismatch')
        if q['kind']=='ack' and (q['response_sha256']!=state['response_sha256'] or q['next_receipt_sha256']!=state['next_receipt_sha256']): raise ValueError('ack mismatch')
        if token is not None: raise ValueError('unexpected token')
    nonce_book.add(replay)
    return fp

def parse_request_json(data):
    import json
    def pairs(items):
        d={}
        for k,v in items:
            if k in d: raise ValueError('duplicate JSON key')
            d[k]=v
        return d
    if len(data.encode('utf-8'))>1048576: raise ValueError('envelope too long')
    envelope=json.loads(data,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('JSON constant')))
    if type(envelope) is not dict or set(envelope)!={'request','signature','token'}: raise ValueError('envelope fields')
    q=envelope['request']
    if type(q) is not dict or set(q)!={k for k,_ in REQUEST_FIELDS}: raise ValueError('request fields')
    for k,t in REQUEST_FIELDS:
        if t=='b': q[k]=unb64(q[k])
    request_bytes(q)
    sig=unb64(envelope['signature'])
    if len(sig)!=64: raise ValueError('signature length')
    token=envelope['token']
    if q['kind']=='issue':
        token=unb64(token)
        if not 1<=len(token)<=16384: raise ValueError('token length')
    elif token is not None: raise ValueError('unexpected token')
    return q,sig,token

def handle_tag(key, handle):
    if key['id']!=handle['handle_key_id'] or len(handle['child_key_sha256'])!=32: raise ValueError('handle key binding')
    return mac(key,'delegation-handle-authentication','PACT-DELEGATION-HANDLE-v1',HANDLE_FIELDS,handle)

def action_bytes(action):
    if action['method']!='POST' or action['route']!='/pact-reference/v1/actions/execute': raise ValueError('action route')
    if len(action['handle_sha256'])!=32 or len(action['nonce'])!=32 or len(action['authority'])!=1: raise ValueError('action cardinality/digest')
    return encode('PACT-CHILD-ACTION-PROOF-v1',ACTION_FIELDS,action)

def action_fixture():
    key={'id':'handle-test-1','purpose':'delegation-handle-authentication','secret':bytes(range(160,192))}
    private=Ed25519PrivateKey.from_private_bytes(bytes(range(192,224)))
    handle=dict(handle_key_id=key['id'],issuer='authority-service-1',delegation='child-delegation-1',root='root-1',session='session-1',parent='parent-delegation-1',child='child-1',child_key_sha256=sha(private.public_key().public_bytes_raw()),supervisor='supervisor-1',provider='provider-1',client='client-1',authority=[['repo-A','read-diff','diff','diff-D']],expiry_ms=180000,budget=0,epoch=2)
    tag=handle_tag(key,handle)
    action=dict(method='POST',route='/pact-reference/v1/actions/execute',authority_id='supervisor-1',delegation=handle['delegation'],root=handle['root'],session=handle['session'],parent=handle['parent'],child=handle['child'],epoch=2,handle_sha256=sha(encode('PACT-DELEGATION-HANDLE-v1',HANDLE_FIELDS,handle)+lp(tag)),provider=handle['provider'],client=handle['client'],authority=handle['authority'],signed_at_ms=100000,nonce=bytes(range(224,256)))
    return key,private,handle,tag,action

def fixtures():
    receipt_key={'id':'receipt-test-1','purpose':'receipt-authentication','secret':bytes(range(32))}
    commitment_key={'id':'commit-test-1','purpose':'token-commitment','secret':bytes(range(32,64))}
    private=Ed25519PrivateKey.from_private_bytes(bytes(range(64,96)))
    pub=private.public_key().public_bytes_raw()
    token=b'DUMMY-NONSECRET-refresh-token'
    r=dict(receipt_key_id=receipt_key['id'],commitment_key_id=commitment_key['id'],root='root-1',consent='consent-1',principal='human-1',session='session-1',capability='repository',provider='provider-1',client='client-1',enc_key_sha256=sha(X25519PrivateKey.from_private_bytes(bytes(range(32))).public_key().public_bytes_raw()),sign_key_sha256=sha(pub),authority=[['repo-A','read-diff','diff','diff-D']],refreshable=True,deadline_ms=200000,epoch=2,generation=3,commitment=bytes(32))
    r['commitment']=commitment(commitment_key,r,token)
    tag=receipt_tag(receipt_key,r)
    q=dict(kind='issue',method='POST',route=ROUTES['issue'],authority_id='authority-1',root=r['root'],session=r['session'],generation=3,epoch=2,receipt_sha256=receipt_digest(r,tag),token_sha256=sha(token),operation_id='operation-1',response_sha256=bytes(32),next_receipt_sha256=bytes(32),signed_at_ms=100000,nonce=bytes(range(96,128)))
    state=dict(root=r['root'],session=r['session'],epoch=2,authority_id=q['authority_id'],sign_key_sha256=r['sign_key_sha256'],approved_receipt=r,phase='RENEWAL_ACTIVE',generation=3)
    return receipt_key,commitment_key,private,token,r,tag,q,state

if __name__=='__main__':
    import json
    rk,ck,p,t,r,tag,q,state=fixtures()
    def wire(x):
        if isinstance(x,bytes): return b64(x)
        if isinstance(x,dict): return {k:wire(v) for k,v in x.items()}
        if isinstance(x,list): return [wire(v) for v in x]
        return x
    result={'status':'PROPOSED REFERENCE ONLY; ALL KEYS AND TOKENS PUBLIC DUMMY MATERIAL','receipt_key':wire(rk),'commitment_key':wire(ck),'ed25519_seed':b64(bytes(range(64,96))),'ed25519_public':b64(p.public_key().public_bytes_raw()),'x25519_public':b64(X25519PrivateKey.from_private_bytes(bytes(range(32))).public_key().public_bytes_raw()),'token':b64(t),'receipt':wire(r),'receipt_payload_hex':receipt_bytes(r).hex(),'receipt_tag':b64(tag),'request':wire(q),'request_payload_hex':request_bytes(q).hex(),'signature':b64(sign(p,q)),'operation_fingerprint':b64(fingerprint(q))}
    hk,hp,handle,ht,action=action_fixture()
    result['child_action']={'handle_key':wire(hk),'ed25519_seed':b64(bytes(range(192,224))),'ed25519_public':b64(hp.public_key().public_bytes_raw()),'handle':wire(handle),'handle_payload_hex':encode('PACT-DELEGATION-HANDLE-v1',HANDLE_FIELDS,handle).hex(),'handle_authenticator':b64(ht),'action':wire(action),'action_payload_hex':action_bytes(action).hex(),'signature':b64(hp.sign(action_bytes(action)))}
    result['requests']=[]
    for kind in ('issue','retrieve','ack'):
        attempt={**q,'kind':kind,'route':ROUTES[kind],'signed_at_ms':100000+len(result['requests']),'nonce':bytes([len(result['requests'])+1])*32}
        if kind=='ack': attempt.update(response_sha256=sha(b'DUMMY-sealed-response'),next_receipt_sha256=sha(b'DUMMY-next-receipt'))
        result['requests'].append({'kind':kind,'request':wire(attempt),'payload_hex':request_bytes(attempt).hex(),'signature':b64(sign(p,attempt)),'operation_fingerprint':b64(fingerprint(attempt))})
    print(json.dumps(result,indent=2))
