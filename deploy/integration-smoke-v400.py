#!/usr/bin/env python3
"""Read-only authenticated SSO API checks. Token read from stdin, never command-line output."""
import argparse,json,sys,urllib.request,urllib.error,urllib.parse
p=argparse.ArgumentParser();p.add_argument('--base-url',required=True);p.add_argument('--org-id',required=True);args=p.parse_args()
base=args.base_url.rstrip('/')
if urllib.parse.urlsplit(base).scheme!='https':p.error('Use the public HTTPS SSO URL')
token=sys.stdin.read().strip()
if not token:p.error('Supply an access token on stdin')
failed=False
for suffix in ['/v1/organizations/'+urllib.parse.quote(args.org_id,safe='')+'/members','/v1/organizations/'+urllib.parse.quote(args.org_id,safe='')+'/applications']:
    req=urllib.request.Request(base+suffix,headers={'Authorization':'Bearer '+token,'Accept':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=15) as response:data=json.load(response)
        key='members' if suffix.endswith('/members') else 'applications'
        print(key+': PASS ('+str(len(data.get(key,[])))+' entries)')
    except Exception as exc:print(suffix+': FAIL ('+type(exc).__name__+')');failed=True
sys.exit(1 if failed else 0)
