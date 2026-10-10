import { useEffect, useRef, useState } from 'react';
import { ApiError, counts, investigate, methodLabel, sourceName, sourceUrl, stateClass, stateLabel, stateSymbol, STATES,
  type Claim, type Evidence, type EvidenceState, type Fixture, type Investigation } from './contract';

function Mark(){return <svg width="25" height="25" viewBox="0 0 28 28" fill="none" aria-hidden="true"><path d="M5 23V5h18M12 23V12h11" stroke="currentColor" strokeWidth="1.8"/></svg>;}
function Arrow(){return <span aria-hidden="true">↗</span>;}
function Status({state}:{state:EvidenceState}){return <span className={`status ${stateClass(state)}`}><span className="state-icon" aria-hidden="true">{stateSymbol(state)}</span><span>{stateLabel(state)}</span></span>;}
function RawRecord({value,label='Raw evidence'}:{value:unknown;label?:string}){const [open,setOpen]=useState(false);return <details className="raw-record" onToggle={e=>setOpen(e.currentTarget.open)}><summary>{label}</summary>{open&&<pre>{JSON.stringify(value,null,2)}</pre>}</details>;}
function ClaimNode({claim,title,detail,selected,onSelect}:{claim:Claim;title:string;detail:string;selected:boolean;onSelect:(id:string)=>void}){
  return <button className={`claim-node ${stateClass(claim.evidence_state)} ${selected?'selected':''}`} aria-pressed={selected} onClick={()=>onSelect(claim.id)}>
    <span className="node-top"><span className="eyebrow">{title}</span><span className="node-index">{claim.id.toUpperCase()}</span></span>
    <strong>{detail}</strong><Status state={claim.evidence_state}/><span className="node-open" aria-hidden="true">↗</span>
  </button>;
}
function Relationship({result,selected,onSelect}:{result:Investigation;selected:string;onSelect:(id:string)=>void}){
  const entity=result.claims.find(c=>c.kind==='legal_entity');const reg=result.claims.find(c=>c.kind==='regulated_firm');
  const affiliation=result.claims.find(c=>c.kind==='clone_affiliation');const contact=result.claims.find(c=>c.kind==='regulated_contact');
  const fca=result.evidence.find(e=>e.method==='regulator_record_lookup');
  const genuine=reg?.organization??entity?.organization??affiliation?.organization??'Claimed organization';
  const frn=typeof fca?.observations.frn==='string'?fca.observations.frn:'Regulatory reference';
  const clone=typeof fca?.observations.clone_name==='string'?fca.observations.clone_name.replace(/\s*\(.*$/,''):'Claimed contacting brand';
  const contactEvidence=result.evidence.find(e=>e.method==='regulator_contact_comparison'&&contact?.evidence_ids.includes(e.id));
  const suppliedPhone=contactEvidence?.observations.supplied_phone;
  if(!entity||!reg||!affiliation||!contact||!affiliation.source_quote.toLowerCase().includes('ipo horizon'))return <div className="generic-claims">{result.claims.length?result.claims.map(c=><ClaimNode key={c.id} claim={c} title={methodLabel(c.verification_method)} detail={c.statement} selected={selected===c.id} onSelect={onSelect}/>):<p>No critical claims were established by the extractor. No identity conclusion is available.</p>}</div>;
  return <div className="relationship" aria-label="Evidence relationship graph">
    <div className="firm-heading"><span className="eyebrow">The claimed genuine firm</span><h3>{genuine}</h3></div>
    <div className="branch branch-top" aria-hidden="true"><span/><span/></div>
    <div className="genuine-nodes">
      <ClaimNode claim={entity} title="Legal entity" detail={entity.evidence_state===STATES.VERIFIED?'Active company':'Company status claim'} selected={selected===entity.id} onSelect={onSelect}/>
      <ClaimNode claim={reg} title="Regulator record" detail={frn==='Regulatory reference'?frn:`FRN ${frn}`} selected={selected===reg.id} onSelect={onSelect}/>
    </div>
    <div className={`identity-link ${stateClass(affiliation.evidence_state)}`}><span className="link-line"/><span>{affiliation.evidence_state===STATES.CONTRADICTED?'Claimed connection rejected by FCA':'Claimed connection · '+stateLabel(affiliation.evidence_state)}</span><span className="link-line"/></div>
    <ClaimNode claim={affiliation} title="Contacting brand" detail={clone} selected={selected===affiliation.id} onSelect={onSelect}/>
    <div className="branch branch-bottom" aria-hidden="true"><span/></div>
    <button className={`contact-node ${stateClass(contact.evidence_state)} ${selected===contact.id?'selected':''}`} aria-pressed={selected===contact.id} onClick={()=>onSelect(contact.id)}>
      <span className="node-top"><span className="eyebrow">Claimed official contact</span><span className="node-index">{contact.id.toUpperCase()} · ONE CLAIM</span></span>
      <span className="contact-fields"><span><small>WEBSITE</small><strong>{contact.domain??'Domain not extracted'}</strong></span><span><small>TELEPHONE</small><strong>{typeof suppliedPhone==='string'?suppliedPhone:'Not supplied'}</strong></span></span>
      <Status state={contact.evidence_state}/><span className="node-open" aria-hidden="true">↗</span>
    </button>
    <p className="graph-caption">Select a claim to inspect the source and its boundary.</p>
  </div>;
}
function EvidenceItem({e}:{e:Evidence}){
  const url=sourceUrl(e);const retrieved=e.source_provenance.retrieved_at_utc;
  return <div className="evidence-item"><div className="evidence-item-title"><strong>{methodLabel(e.method)}</strong><span className="mono">{e.id.toUpperCase()}</span></div><Status state={e.evidence_state}/>
    {e.error!=null&&<p className="source-failure">Source failure: {typeof e.error==='object'&&e.error!==null&&'message' in e.error?String(e.error.message):String(e.error)}</p>}
    {url?<a className="source-link" href={url} target="_blank" rel="noopener noreferrer">{sourceName(e)} <Arrow/></a>:<p className="muted">No source URL returned.</p>}
    <p className="evidence-meta">{typeof retrieved==='string'?`Retrieved ${new Date(retrieved).toLocaleString()}`:'Derived or unavailable record'} · {e.latency_ms.toFixed(0)} ms</p>
    <RawRecord value={e.observations} label="Parsed source facts"/>
    <RawRecord value={{source_provenance:e.source_provenance,raw_evidence:e.raw_evidence,error:e.error}}/>
    {e.limitations.length>0&&<details className="raw-record"><summary>Source boundaries</summary><ul>{e.limitations.map((l,i)=><li key={i}>{l}</li>)}</ul></details>}
  </div>;
}
function Inspector({result,claim}:{result:Investigation;claim:Claim|undefined}){
  if(!claim)return <aside className="inspector"><p>Select an extracted claim to inspect its evidence.</p></aside>;
  const records=result.evidence.filter(e=>claim.evidence_ids.includes(e.id));
  const comparison=records.find(e=>e.method==='regulator_contact_comparison')?.observations;
  const groups=new Map<string,Evidence[]>();for(const e of records){const key=e.evidence_group_id??`ungrouped-${e.id}`;groups.set(key,[...(groups.get(key)??[]),e]);}
  return <aside className="inspector" aria-label="Claim evidence inspector"><div className="inspector-heading"><span className="eyebrow">Evidence inspector</span><span className="mono">{claim.id.toUpperCase()}</span></div>
    <div key={claim.id} className="inspector-content"><h3>Claim</h3><blockquote>“{claim.source_quote}”</blockquote><Status state={claim.evidence_state}/>
      <h3>Verification</h3><p>{methodLabel(claim.verification_method)}</p><h3>Finding</h3><p className="finding">{claim.finding}</p>
      {comparison&&typeof comparison.regulator_domain==='string'&&<dl className="comparison-facts"><div><dt>Regulator-published website</dt><dd>{comparison.regulator_domain}</dd></div><div><dt>Supplied website</dt><dd>{String(comparison.supplied_domain)}</dd></div><div><dt>Regulator-published telephone</dt><dd>{String(comparison.regulator_phone)}</dd></div><div><dt>Supplied telephone</dt><dd>{typeof comparison.supplied_phone==='string'?comparison.supplied_phone:'Not supplied'}</dd></div></dl>}
      {claim.limitations.length>0&&<div className="boundary"><h3>What this establishes</h3>{claim.limitations.map((l,i)=><p key={i}>{l}</p>)}</div>}
      <h3>Evidence & provenance</h3>{records.length===0?<p>No authoritative evidence records support this claim.</p>:[...groups].map(([id,items])=><section className="provenance-group" key={id}>
        <div className="group-heading"><strong>{sourceName(items[0])}</strong><small>{items.length} record{items.length===1?'':'s'} · {items[0].evidence_group_id?'one source group':'ungrouped data gap'}</small></div>
        <details className="group-id"><summary>Provenance identity</summary><code>{items[0].evidence_group_id??'No underlying source group established'}</code></details>
        {items.map(e=><EvidenceItem key={e.id} e={e}/>)}</section>)}
    </div>
  </aside>;
}
function Method(){return <section className="method-section" id="method"><div><span className="eyebrow">The method</span><h2>AI decides what needs investigation.<br/><em>Evidence decides what is true.</em></h2></div><div className="method-steps"><div><span>01</span><p><strong>Extract</strong>Grounded factual claims, not an AI verdict.</p></div><div><span>02</span><p><strong>Verify</strong>Independent public records and exact comparisons.</p></div><div><span>03</span><p><strong>Correlate</strong>Find where individually plausible facts conflict.</p></div></div></section>;}
function SourceLedger({result}:{result:Investigation}){
  const groups=new Map<string,Evidence[]>();for(const e of result.evidence){const key=e.evidence_group_id??`ungrouped-${e.id}`;groups.set(key,[...(groups.get(key)??[]),e]);}
  return <section className="ledger" id="evidence"><div className="section-top"><span className="eyebrow">Source ledger</span><span>{String(result.summary.independent_evidence_count??'—')} useful independent groups · {String(result.summary.verification_mechanism_count??'—')} mechanisms</span></div>
    {[...groups].map(([group,items])=>{const root=items.find(e=>e.source_provenance.origin!=='derived_exact_comparison')??items[0];const url=sourceUrl(root);return <div className="ledger-row" key={group}>
      <div><strong>{sourceName(root)}</strong><small>{methodLabel(root.method)}</small></div><Status state={root.evidence_state}/><div><small>{items.length} evidence record{items.length===1?'':'s'}</small><details className="group-id"><summary>Technical provenance</summary><code>{root.evidence_group_id??'No source group'}</code></details></div>{url?<a href={url} target="_blank" rel="noopener noreferrer">View source <Arrow/></a>:<span>Unavailable</span>}
    </div>;})}
    <p className="ledger-note">Findings are not independent sources. Multiple FCA facts and their derived comparisons share one provenance group.</p>
  </section>;
}
function Pending({message,onCancel,annotated}:{message:string;onCancel:()=>void;annotated:boolean}){
  const [seconds,setSeconds]=useState(0);useEffect(()=>{const start=performance.now();const timer=setInterval(()=>setSeconds(Math.floor((performance.now()-start)/1000)),1000);return()=>clearInterval(timer);},[]);
  return <section className="pending-workbench"><div className="submitted"><span className="eyebrow">Submitted communication</span><blockquote>{message}</blockquote><span className="quiet-caption">Preserved as submitted. Its assertions are not evidence.</span></div><div className="progress-panel" role="status" aria-live="polite"><span className="eyebrow">Investigation in progress</span><h1>Checking whether<br/><em>the facts belong together.</em></h1><div className="live-request"><span className="spinner"/><span>{annotated?'Live source investigation requested':'Claim extraction and investigation requested'}</span><span className="mono">{seconds}s</span></div>
    <div className="pending-methods"><div><span>01</span><strong>{annotated?'Analyst-annotated claims':'Grounded claim extraction'}</strong></div><div><span>02</span><strong>Regulator and legal-entity records</strong></div><div><span>03</span><strong>Contact comparison and domain provenance</strong></div><div><span>04</span><strong>Evidence correlation</strong></div></div>
    <p className="progress-boundary">The API returns findings together. Individual checks are not marked complete until their real evidence arrives.</p><button className="text-button" onClick={onCancel}>Stop waiting <span aria-hidden="true">×</span></button>
  </div></section>;
}

export default function App(){
  const [message,setMessage]=useState('');const [fixture,setFixture]=useState<Fixture|null>(null);const [fixtureError,setFixtureError]=useState('');
  const [result,setResult]=useState<Investigation|null>(null);const [selected,setSelected]=useState('');const [busy,setBusy]=useState(false);
  const [error,setError]=useState<Error|null>(null);const request=useRef<AbortController|null>(null);const heading=useRef<HTMLHeadingElement>(null);
  useEffect(()=>{const c=new AbortController();fetch('/fixture',{signal:c.signal}).then(r=>{if(!r.ok)throw new Error('The example could not be loaded from the server.');return r.json();}).then((data:Fixture)=>{if(typeof data.message!=='string'||typeof data.annotation_mode!=='boolean')throw new Error('The example response is malformed.');setFixture(data);}).catch(e=>{if(e.name!=='AbortError')setFixtureError(e.message);});return()=>{c.abort();request.current?.abort();};},[]);
  useEffect(()=>{if(result){heading.current?.focus();window.scrollTo({top:0,behavior:'instant'});}},[result]);
  const annotated=Boolean(fixture?.annotation_mode&&fixture.message===message);
  async function submit(){
    if(request.current||!message.trim())return;const c=new AbortController();request.current=c;setBusy(true);setError(null);
    try{const value=await investigate(message,fixture,c.signal);if(request.current!==c)return;setResult(value);setSelected(value.claims.find(v=>v.kind==='clone_affiliation')?.id??value.claims[0]?.id??'');}
    catch(e){if(request.current===c)setError(e instanceof Error?e:new Error(String(e)));}
    finally{if(request.current===c){request.current=null;setBusy(false);}}
  }
  function cancel(){request.current?.abort();request.current=null;setBusy(false);setError(new Error('You stopped waiting. The server may still be finishing its request; no results have been substituted.'));}
  function reset(){request.current?.abort();request.current=null;setResult(null);setBusy(false);setError(null);setMessage('');window.scrollTo({top:0,behavior:'instant'});}
  const totals=result?counts(result):null;
  const meaningfulConflict=Boolean(result&&['legal_entity','regulated_firm'].every(kind=>result.claims.some(c=>c.kind===kind&&c.evidence_state===STATES.VERIFIED))&&['clone_affiliation','regulated_contact'].every(kind=>result.claims.some(c=>c.kind===kind&&c.evidence_state===STATES.CONTRADICTED)));
  const identityConflict=Boolean(result?.claims.some(c=>['clone_affiliation','regulated_contact'].includes(c.kind)&&c.evidence_state===STATES.CONTRADICTED));
  return <><a className="skip-link" href="#main">Skip to investigation</a><header className="site-header"><button className="brand" onClick={reset} aria-label="CrossCheck — new investigation"><Mark/><span>CrossCheck</span><small>Evidence workbench</small></button><nav aria-label="Main navigation"><a href="#method">Method</a><a href="#evidence">Evidence</a></nav></header>
    <main id="main" className={result?'result-main':'input-main'}>
      {busy?<Pending message={message} onCancel={cancel} annotated={annotated}/>:result&&totals?<>
        <div className="result-heading"><div><span className="eyebrow">Investigation / findings</span><h1 ref={heading} tabIndex={-1}>{totals.contradicted?(identityConflict?'Identity inconsistency detected':'Claim inconsistencies detected'):totals.unresolved?'Evidence remains unresolved':'Facts checked. Identity still matters.'}</h1><div className="result-counts"><strong>{result.claims.length} claims investigated</strong><span className="verified">✓ {totals.verified} VERIFIED</span><span className="contradicted">× {totals.contradicted} CONTRADICTED</span><span>? {totals.unresolved} UNRESOLVED</span>{totals.consistent>0&&<span>≈ {totals.consistent} CONSISTENT</span>}</div></div><button className="secondary-button" onClick={reset}>New investigation <span aria-hidden="true">↗</span></button></div>
        <div className="result-meta"><span>{result.extraction.used_llm===true?'Live claim extraction':result.extraction.mode==='fixture_annotation'?'Analyst-annotated claims · model not run':'Claim extraction · model not run'} · {(result.latency_ms/1000).toFixed(2)}s backend processing</span><span>Conclusion from evidence. No identity authentication implied.</span></div>
        {result.evidence.some(e=>e.error!=null)&&<div className="gap-banner" role="status">Some source checks failed or remain unavailable. See the source ledger; missing evidence has not been converted into a contradiction.</div>}
        <section className="evidence-workspace"><div className="graph-panel"><div className="section-top"><span className="eyebrow">Evidence relationship</span><span className="quiet-caption">Real records. Claimed connection.</span></div><Relationship result={result} selected={selected} onSelect={setSelected}/></div><Inspector result={result} claim={result.claims.find(c=>c.id===selected)}/></section>
        <section className="payoff"><span className="eyebrow">The distinction that matters</span><h2>{meaningfulConflict?'Real facts can still form a fake identity.':'Public facts do not authenticate a contacting party.'}</h2><p>{meaningfulConflict?'The company and registration are genuine. The claimed connection and contact channel conflict with the regulator’s record. The genuine facts do not transfer an identity to the contacting party.':result.evidence_correlation?.finding?String(result.evidence_correlation.finding):'Use the established findings and their boundaries. Unresolved claims are gaps, not proof of impersonation.'}</p></section>
        <SourceLedger result={result}/><details className="case-notes"><summary>Original communication & investigation boundaries</summary><blockquote>{result.input.message}</blockquote><ul>{result.limitations.map((l,i)=><li key={i}>{l}</li>)}</ul><RawRecord value={result} label="Complete backend response"/></details>
      </>:<>
        <section className="intro"><div><span className="eyebrow"><span className="small-line"/> Evidence-backed impersonation investigation</span><h1>Verify the story.<br/><em>Not just the message.</em></h1><p>A suspicious message can contain real companies,<br className="desktop-break"/> real registrations and real people.<br className="desktop-break"/> We check whether those facts actually belong together.</p></div><div className="intro-note"><span className="note-index">01—</span><p>A genuine company.<br/>A genuine registration.<br/><em>A different identity.</em></p><span className="quiet-caption">Investigate the connection,<br/>not just the individual facts.</span></div></section>
        <form className="input-surface" onSubmit={e=>{e.preventDefault();void submit();}}><div className="input-heading"><label htmlFor="communication">Material for investigation</label><span>01 / COMMUNICATION</span></div><textarea id="communication" value={message} maxLength={64000} required onChange={e=>{setMessage(e.target.value);setError(null);}} placeholder="Paste a message that claims to represent a company, a regulated firm or an official contact…" aria-describedby="input-boundary"/>
          <div className="input-footer"><div><button type="button" className="example-button" disabled={!fixture} onClick={()=>{if(fixture){setMessage(fixture.message);setError(null);}}}>Load flagship example <span aria-hidden="true">→</span></button><small>IPO Horizon / Horizon Financial Planning</small></div><button className="primary-button" disabled={!message.trim()}>Investigate claims <span aria-hidden="true">→</span></button></div>
        </form><div id="input-boundary" className="input-footnote"><span>No probability score. Every conclusion is tied to evidence.</span><span>{message.length.toLocaleString()} / 64,000 characters</span></div>
        {fixture&&message===fixture.message&&<p className="example-notice">Illustrative communication based on the FCA clone-firm warning. {annotated?'This run uses explicitly labelled analyst annotations; all source checks run live.':'Claims will be extracted by the live model; source checks run live.'}</p>}
        {fixtureError&&<p className="source-failure" role="alert">{fixtureError} You can still submit your own communication.</p>}
        {error&&<section className="error-panel" role="alert"><div><span className="eyebrow">Investigation could not be completed</span><h2>No findings have been substituted.</h2><p>{error.message}</p>{error instanceof ApiError&&<><p className="mono">Backend HTTP {error.status}</p><RawRecord value={error.detail} label="Backend failure details"/></>}</div><button className="secondary-button" onClick={()=>void submit()} disabled={!message.trim()}>Try again →</button></section>}
        <section className="input-evidence" id="evidence"><span className="eyebrow">Public records. Inspectable provenance.</span><div><span>Financial Conduct Authority</span><span>Companies House</span><span>Authoritative RDAP</span></div><p>When applicable, every returned finding includes its source, method and limitations.</p></section>
      </>}
      {!busy&&<Method/>}
    </main><footer className="site-footer"><span><strong>CrossCheck</strong> The facts are only the beginning.</span><span>Evidence-backed investigation · Hackathon edition</span></footer>
  </>;
}
