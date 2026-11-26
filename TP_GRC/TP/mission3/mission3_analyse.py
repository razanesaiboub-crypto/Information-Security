import argparse, json
from collections import Counter
from pathlib import Path
import pandas as pd
from wordcloud import WordCloud

ap=argparse.ArgumentParser()
ap.add_argument('--source',default='mission2_corrected')
ap.add_argument('--out',default='mission3')
ap.add_argument('--sites',nargs=3,default=['https://www.microsoft.com','https://dolcevita.com','https://ico.org'])
a=ap.parse_args(); src=Path(a.source); out=Path(a.out)
if out.exists(): raise SystemExit('Output already exists; use --out with a new folder name.')
df=pd.read_csv(src/'mission2_results.csv'); cookies=pd.read_csv(src/'cookies.csv'); reqs=json.loads((src/'requests.json').read_text(encoding='utf-8'))
if len(df)!=10 or df.total_requests.sum()!=len(reqs) or df.total_cookies.sum()!=len(cookies): raise SystemExit('Mission 2 evidence incomplete or inconsistent.')
valid=set(df.loc[df.navigation_error.isna() & df.main_status.between(200,399),'website'])
print('Cookie counts (valid visits):\n',cookies[cookies.website.isin(valid)].groupby('website').size().to_string())
if len(set(a.sites))!=3 or not set(a.sites)<=valid or any((cookies.website==s).sum()<3 for s in a.sites): raise SystemExit('Choose three distinct valid websites with at least three cookies each using --sites URL1 URL2 URL3.')
out.mkdir()
chosen=cookies[cookies.website.isin(a.sites)].copy()
chosen.insert(0,'cookie_id',range(1,len(chosen)+1))
chosen['likely_purpose']='Unknown'; chosen['classification_source']=''; chosen['potential_identifier']='Unknown'; chosen['reasoning']=''
chosen.to_csv(out/'cookie_candidates.csv',index=False)
print('\nCookie candidates:\n',chosen[['cookie_id','website','cookie_name','cookie_domain','party','type']].to_string(index=False))
rows=[]
for r in reqs:
    if r['website'] not in valid: continue
    for source,keys in [('query',r['query_keys']),('POST',r['post_keys'])]:
        for key in keys: rows.append({k:r[k] for k in ['request_id','website','destination','endpoint','method','party','response_status']}|{'source':source,'parameter':key})
pd.DataFrame(rows,columns=['request_id','website','destination','endpoint','method','party','response_status','source','parameter']).to_csv(out/'parameters.csv',index=False)
counts=Counter(r['parameter'] for r in rows)
pd.DataFrame(counts.most_common(),columns=['parameter','frequency']).to_csv(out/'parameter_frequency.csv',index=False)
if counts: WordCloud(width=1400,height=800,background_color='white',random_state=42).generate_from_frequencies(counts).to_file(str(out/'wordcloud.png'))
print('\nTop 30 parameters:',counts.most_common(30)); print('Parameter source counts:',dict(Counter(r['source'] for r in rows)))
print('POST body parsing outcomes:',dict(Counter(r['post_format'] for r in reqs if r['website'] in valid and r['method']=='POST')))
pd.DataFrame([{'request_id':'','parameter':'','possible_meaning':'','classification_source':'','privacy_implication':''} for _ in range(3)]).to_csv(out/'request_investigation_template.csv',index=False)
pd.DataFrame([{'finding':i,'technical_evidence':'','potential_processing':'','GDPR_requirement':'','additional_evidence':'','classification':'','risk':'','recommended_control':''} for i in (1,2)]).to_csv(out/'findings_template.csv',index=False)
print('Mission 3 evidence ready. Classify nine cookies, investigate three distinct request IDs, and write two findings using documentation. No new browser visits were made.')
