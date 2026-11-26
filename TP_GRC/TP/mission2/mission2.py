import argparse, hashlib, json, re, statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl, urlencode
import requests
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import tldextract
from playwright.sync_api import sync_playwright

TRACKER_URL = 'https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json'
WAIT_MS = 5000
extract = tldextract.TLDExtract(suffix_list_urls=())

def now(): return datetime.now(timezone.utc).isoformat()
def domain(host):
    host = (host or '').lower().strip('.')
    return extract(host).top_domain_under_public_suffix or host

def json_keys(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield str(key)
            yield from json_keys(value)
    elif isinstance(obj, list):
        for item in obj: yield from json_keys(item)

def post_info(req):
    try:
        body = req.post_data
        if not body: return [], 'no_body'
        ct = req.headers.get('content-type','').lower()
        if 'json' in ct:
            return list(json_keys(json.loads(body))), 'json'
        if 'application/x-www-form-urlencoded' in ct:
            return [k for k,v in parse_qsl(body,keep_blank_values=True)], 'form'
        if 'multipart/form-data' in ct:
            return re.findall(r'(?im)^Content-Disposition: form-data;[^\r\n]*?\bname="([^"\r\n]+)"',body), 'multipart'
        return [], 'unsupported'
    except Exception: return [], 'parse_error'

def safe_endpoint(url):
    p=urlsplit(url)
    # Do not export query values or full bodies. Mask long path components.
    path=re.sub(r'/[^/]{24,}', '/[REDACTED]', p.path)
    return p.scheme+'://'+(p.hostname or '')+path

def tracker_map(data):
    mapping={}
    for category, entries in data['categories'].items():
        for entry in entries:
            for details in entry.values():
                if not isinstance(details,dict): continue
                for items in details.values():
                    if not isinstance(items,list): continue
                    for item in items:
                        if isinstance(item,str) and re.fullmatch(r'[a-zA-Z0-9.-]+\.[a-zA-Z0-9-]+',item):
                            mapping.setdefault(item.lower().strip('.'),set()).add(category)
    return mapping

def categories(host, mapping):
    labels=set()
    parts=host.lower().strip('.').split('.')
    for i in range(len(parts)): labels.update(mapping.get('.'.join(parts[i:]),set()))
    return sorted(labels)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--sites',default='colleagues/TP/websites.csv')
    ap.add_argument('--out',default='mission2_corrected')
    ap.add_argument('--ranking-id',default='Unknown (original snapshot not supplied)')
    ap.add_argument('--tracker-file',help='Optional previously downloaded Disconnect services.json')
    args=ap.parse_args()
    out=Path(args.out)
    if out.exists(): raise SystemExit('Output folder already exists. Use --out with a new folder name to preserve evidence.')
    sites=pd.read_csv(args.sites)
    assert len(sites)==10 and sites.url.nunique()==10, 'Expected ten distinct websites'
    out.mkdir(); (out/'screenshots').mkdir()
    raw=Path(args.tracker_file).read_bytes() if args.tracker_file else requests.get(TRACKER_URL,timeout=60).content
    data=json.loads(raw); mapping=tracker_map(data)
    if not mapping: raise RuntimeError('Tracker list empty')
    (out/'services.json').write_bytes(raw)
    (out/'tracker_domains.txt').write_text('\n'.join(sorted(mapping)),encoding='utf-8')
    sites.to_csv(out/'websites.csv',index=False)
    meta={'tracker_source':args.tracker_file or TRACKER_URL,'tracker_snapshot_saved_at':now(),'tracker_sha256':hashlib.sha256(raw).hexdigest(),'tracker_domain_count':len(mapping),'tracker_rule':'Third-party domain match; exclude Content-only matches; all-category matches also exported','ranking_id':args.ranking_id,'wait_ms':WAIT_MS,'browser_context':'Playwright default fresh context; no login or interaction','party_rule':'Final top-level registrable domain, original requested domain retained','cookie_lifetime':'Remaining lifetime at inventory snapshot','privacy':'Query and body values omitted; long path segments masked; inspect exports before sharing'}
    (out/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')
    summaries=[]; all_requests=[]; all_cookies=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=False)
        for site in sites.itertuples(index=False):
            url=site.url; local=[]; statuses={}; failures={}; error=''; main_status=None
            context=browser.new_context(); page=context.new_page()
            def capture(req):
                parts=urlsplit(req.url)
                if parts.scheme not in ('http','https'): return
                host=parts.hostname or ''
                keys,fmt=post_info(req)
                local.append((req,{'website':url,'method':req.method,'destination':host,'domain':domain(host),'endpoint':safe_endpoint(req.url),'query_keys':[k for k,v in parse_qsl(parts.query,keep_blank_values=True)],'post_keys':keys,'post_format':fmt,'resource_type':req.resource_type}))
            page.on('request',capture)
            page.on('response',lambda res:statuses.update({res.request:res.status}))
            page.on('requestfailed',lambda req:failures.update({req:req.failure}))
            print('\nAuditing:',url,flush=True)
            start=now()
            try:
                response=page.goto(url,wait_until='domcontentloaded',timeout=60000)
                main_status=response.status if response else None
                page.wait_for_timeout(WAIT_MS)
            except Exception as e: error=type(e).__name__
            final_host=urlsplit(page.url).hostname or ''
            target=domain(final_host) or domain(urlsplit(url).hostname)
            stamp=now(); ts=datetime.now(timezone.utc).timestamp()
            cookies=context.cookies(); req_rows=[]; cookie_rows=[]
            for req,row in local:
                third=row['domain']!=target; cats=categories(row['destination'],mapping)
                row.update(request_id=len(all_requests)+len(req_rows)+1,measurement_date=stamp,party='Third-party' if third else 'First-party',tracker_categories=cats,tracker_match_all_categories=bool(third and cats),tracker_match=bool(third and any(c.lower()!='content' for c in cats)),response_status=statuses.get(req),failure=failures.get(req))
                req_rows.append(row)
            for c in cookies:
                expiry=c['expires']; persistent=expiry>0
                cookie_rows.append({'website':url,'measurement_date':stamp,'cookie_name':c['name'],'cookie_domain':c['domain'],'party':'First-party' if domain(c['domain'])==target else 'Third-party','type':'Persistent' if persistent else 'Session','expiry':datetime.fromtimestamp(expiry,timezone.utc).isoformat() if persistent else None,'remaining_days':max(0,expiry-ts)/86400 if persistent else None,'value_length':len(c['value']),'secure':c['secure'],'http_only':c['httpOnly'],'same_site':c['sameSite']})
            third=[r for r in req_rows if r['party']=='Third-party']; persistent=[c['remaining_days'] for c in cookie_rows if c['type']=='Persistent']
            first_c=sum(c['party']=='First-party' for c in cookie_rows)
            summary={'website':url,'group':site.group,'tranco_rank':site.tranco_rank,'measurement_start':start,'measurement_date':stamp,'browser':'Chromium','browser_version':browser.version,'headless':False,'wait_time_ms':WAIT_MS,'requested_domain':domain(urlsplit(url).hostname),'final_host':final_host,'final_domain':target,'navigation_error':error,'main_status':main_status,'total_requests':len(req_rows),'first_party_requests':len(req_rows)-len(third),'third_party_requests':len(third),'distinct_third_party_domains':len({r['domain'] for r in third}),'tracker_matches':sum(r['tracker_match'] for r in req_rows),'tracker_matches_all_categories':sum(r['tracker_match_all_categories'] for r in req_rows),'total_cookies':len(cookie_rows),'first_party_cookies':first_c,'third_party_cookies':len(cookie_rows)-first_c,'session_cookies':len(cookie_rows)-len(persistent),'persistent_cookies':len(persistent),'median_cookie_lifetime_days':statistics.median(persistent) if persistent else None,'max_cookie_lifetime_days':max(persistent) if persistent else None,'network_failures':sum(bool(r['failure']) for r in req_rows)}
            summaries.append(summary); all_requests.extend(req_rows); all_cookies.extend(cookie_rows)
            try: page.screenshot(path=str(out/'screenshots'/((urlsplit(url).hostname or 'site')+'.png')),timeout=10000)
            except Exception: print('Screenshot unavailable')
            context.close()
            print('Requests:',summary['total_requests'],'| Third-party:',len(third),'| Trackers:',summary['tracker_matches'],'| Cookies:',len(cookie_rows),'| Status:',main_status,'| Error:',error or 'None',flush=True)
            # Incremental exports preserve completed visits if later visits fail.
            pd.DataFrame(summaries).to_csv(out/'mission2_results.csv',index=False)
            (out/'requests.json').write_text(json.dumps(all_requests,indent=2),encoding='utf-8')
            pd.DataFrame(all_cookies,columns=['website','measurement_date','cookie_name','cookie_domain','party','type','expiry','remaining_days','value_length','secure','http_only','same_site']).to_csv(out/'cookies.csv',index=False)
        browser.close()
    df=pd.DataFrame(summaries)
    assert (df.total_requests==df.first_party_requests+df.third_party_requests).all()
    assert (df.total_cookies==df.first_party_cookies+df.third_party_cookies).all()
    assert (df.total_cookies==df.session_cookies+df.persistent_cookies).all()
    assert sum(df.total_requests)==len(all_requests) and sum(df.total_cookies)==len(all_cookies)
    valid=df[(df.navigation_error=='') & df.main_status.between(200,399)].copy()
    metrics=['total_requests','third_party_requests','tracker_matches','distinct_third_party_domains','total_cookies','median_cookie_lifetime_days','max_cookie_lifetime_days']
    if len(valid):
        med=valid.groupby('group')[metrics].median(); med.to_csv(out/'group_comparison.csv'); print('\nGroup medians:\n',med.to_string())
        ax=med[['total_requests','third_party_requests','tracker_matches']].plot(kind='bar',figsize=(10,6)); ax.set_ylabel('Median requests'); ax.set_title('Median network activity by group'); plt.xticks(rotation=0); plt.tight_layout(); plt.savefig(out/'figure1_group_comparison.png',dpi=160); plt.close()
        ax=valid.set_index('website')[['first_party_requests','third_party_requests']].plot(kind='bar',stacked=True,figsize=(12,6)); ax.set_ylabel('Observed requests'); ax.set_title('First-party and third-party requests'); plt.xticks(rotation=45,ha='right'); plt.tight_layout(); plt.savefig(out/'figure2_request_distribution.png',dpi=160); plt.close()
        rho=valid.tranco_rank.corr(valid.total_cookies,method='spearman') if len(valid)>2 else float('nan')
        print('Spearman rank vs cookies:',rho)
        print('Valid visits per group:',valid.groupby('group').size().to_dict())
    print('All rows retained; group figures exclude navigation errors/non-2xx/3xx status. Check screenshots for CAPTCHAs or error pages.')
    print('All arithmetic and evidence-count checks passed. Output:',out)

if __name__=='__main__': main()
