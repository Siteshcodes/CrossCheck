export const STATES = {
  VERIFIED: 'VERIFIED_BY_AUTHORITATIVE_SOURCE', CONTRADICTED: 'CONTRADICTED_BY_AUTHORITATIVE_SOURCE',
  CONSISTENT: 'CONSISTENT_BUT_NOT_IDENTITY_PROVING', UNRESOLVED: 'NO_AUTHORITATIVE_DATA',
} as const;
export type EvidenceState = typeof STATES[keyof typeof STATES];
export type Claim = {id:string; kind:string; statement:string; source_quote:string; organization:string|null; domain:string|null;
  evidence_state:EvidenceState; verification_method:string; evidence_ids:string[]; finding:string; limitations:string[]};
export type Evidence = {id:string; method:string; evidence_state:EvidenceState; raw_evidence:unknown;
  source_provenance:Record<string,unknown>; observations:Record<string,unknown>; limitations:string[]; latency_ms:number;
  error:unknown; evidence_group_id:string|null};
export type Investigation = {schema_version:string; status:string; scenario?:string; input:{message:string; origin:string};
  extraction:Record<string,unknown>; claims:Claim[]; evidence:Evidence[]; summary:Record<string,unknown>;
  limitations:string[]; explanation:string; latency_ms:number; evidence_correlation?:Record<string,unknown>};
export type Fixture = {message:string; origin:string; annotation_mode:boolean; claims_annotation?:unknown};
const object=(x:unknown):x is Record<string,unknown>=>typeof x==='object'&&x!==null&&!Array.isArray(x);
const strings=(x:unknown):x is string[]=>Array.isArray(x)&&x.every(v=>typeof v==='string');
const validState=(x:unknown):x is EvidenceState=>Object.values(STATES).includes(x as EvidenceState);
export function parseInvestigation(value:unknown):Investigation {
  if(!object(value)||!Array.isArray(value.claims)||!Array.isArray(value.evidence)||!object(value.input)||typeof value.input.message!=='string'||
    !object(value.extraction)||!object(value.summary)||!strings(value.limitations)||typeof value.explanation!=='string'||typeof value.latency_ms!=='number')
    throw new Error('The backend returned an incomplete investigation response. No conclusion can be displayed.');
  for(const c of value.claims) if(!object(c)||typeof c.id!=='string'||typeof c.kind!=='string'||typeof c.statement!=='string'||typeof c.source_quote!=='string'||
    !validState(c.evidence_state)||!strings(c.evidence_ids)||!strings(c.limitations)||typeof c.finding!=='string'||typeof c.verification_method!=='string')
    throw new Error('The backend returned a malformed claim or unknown evidence state.');
  for(const e of value.evidence) if(!object(e)||typeof e.id!=='string'||typeof e.method!=='string'||!validState(e.evidence_state)||
    !object(e.source_provenance)||!object(e.observations)||!strings(e.limitations)||typeof e.latency_ms!=='number'||
    !(typeof e.evidence_group_id==='string'||e.evidence_group_id===null)) throw new Error('The backend returned malformed evidence.');
  const ids=new Set(value.evidence.map(e=>(e as Evidence).id));
  if(ids.size!==value.evidence.length||new Set(value.claims.map(c=>(c as Claim).id)).size!==value.claims.length||
    value.claims.some(c=>(c as Claim).evidence_ids.some(id=>!ids.has(id)))) throw new Error('The backend returned inconsistent evidence references.');
  return value as Investigation;
}
export const stateLabel=(state:EvidenceState)=>({[STATES.VERIFIED]:'Verified',[STATES.CONTRADICTED]:'Contradicted',[STATES.CONSISTENT]:'Consistent · identity unproven',[STATES.UNRESOLVED]:'Unresolved'})[state];
export const stateClass=(state:EvidenceState)=>({[STATES.VERIFIED]:'verified',[STATES.CONTRADICTED]:'contradicted',[STATES.CONSISTENT]:'consistent',[STATES.UNRESOLVED]:'unresolved'})[state];
export const stateSymbol=(state:EvidenceState)=>({[STATES.VERIFIED]:'✓',[STATES.CONTRADICTED]:'×',[STATES.CONSISTENT]:'≈',[STATES.UNRESOLVED]:'?'})[state];
export const methodLabel=(method:string)=>({regulator_record_lookup:'FCA regulator record',regulator_clone_warning:'FCA named-clone warning',
  regulator_contact_comparison:'Exact regulator contact comparison',legal_entity_registry:'Companies House legal-entity record',
  rdap_domain_provenance:'RDAP domain provenance',candidate_grounding_guard:'Candidate grounding check',identity_boundary:'Identity verification boundary',
  identity_evidence_boundary:'Identity verification boundary',official_recruitment_policy:'Published official policy',
  official_recruiting_domain_comparison:'Official-domain comparison',receiver_reported_spf_dkim_dmarc:'Receiver-reported email authentication'} as Record<string,string>)[method]??method.replaceAll('_',' ');
export function sourceUrl(e:Evidence):string|null {
  const candidate=e.source_provenance.url??e.source_provenance.queried_rdap_url??e.source_provenance.bootstrap_url;
  if(typeof candidate!=='string') return null;
  try{const u=new URL(candidate);return u.protocol==='https:'&&!u.username&&!u.password?u.href:null;}catch{return null;}
}
export function sourceName(e:Evidence):string {
  if(e.method.startsWith('regulator')) return 'Financial Conduct Authority';
  if(e.method==='legal_entity_registry') return 'Companies House';
  if(e.method==='rdap_domain_provenance') return 'RDAP · authoritative registry';
  return 'Evidence record';
}
export function counts(result:Investigation){return {
  verified:result.claims.filter(c=>c.evidence_state===STATES.VERIFIED).length,
  contradicted:result.claims.filter(c=>c.evidence_state===STATES.CONTRADICTED).length,
  unresolved:result.claims.filter(c=>c.evidence_state===STATES.UNRESOLVED).length,
  consistent:result.claims.filter(c=>c.evidence_state===STATES.CONSISTENT).length,
};}
export async function investigate(message:string,fixture:Fixture|null,signal:AbortSignal):Promise<Investigation>{
  const payload={message,...(fixture?.annotation_mode&&fixture.message===message?{claims_annotation:fixture.claims_annotation}:{})};
  const response=await fetch('/investigate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),signal});
  let data:unknown;
  try{data=await response.json();}catch{throw new Error(`The investigation service returned unreadable data (HTTP ${response.status}).`);}
  if(!response.ok){
    const error=object(data)&&object(data.error)?data.error:null;
    const message=typeof error?.message==='string'?error.message:typeof (object(data)?data.error:null)==='string'?String((data as Record<string,unknown>).error):'The investigation could not be completed.';
    throw new ApiError(message,response.status,data);
  }
  return parseInvestigation(data);
}
export class ApiError extends Error {constructor(message:string,public status:number,public detail:unknown){super(message);}}
