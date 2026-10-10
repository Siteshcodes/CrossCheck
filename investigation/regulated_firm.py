"""Curated public regulator and company records. No user-selected sources or LLM truth decisions."""
import base64
from datetime import datetime, timezone
from html.parser import HTMLParser
import re
import time
from urllib.parse import urlsplit

from scam_process_contradictions import fetch_policy, norm
from .models import Evidence, EvidenceState as State, sha256

FCA_URL="https://www.fca.org.uk/news/warnings/ipo-horizon-clone-fca-authorised-firm"
CH_URL="https://find-and-update.company-information.service.gov.uk/company/04333954"
FIRM="Horizon Financial Planning Limited"
COMPANY_NUMBER="04333954"
NO_CONNECTION="This is the genuine, authorised firm that the fraudsters are claiming to work for. It has no connection with the clone firm."
NOT_AUTHORISED="This firm is not authorised by us but has been contacting people pretending to be an authorised firm."


class ScopedHTML(HTMLParser):
    """Read visible text only inside pinned record sections/fields; ignore navigation and scripts."""
    VOID={"area","base","br","col","embed","hr","img","input","link","meta","param","source","track","wbr"}
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack=[]
        self.fields={}
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        key=attrs.get("id")
        if tag=="h1": key="h1"
        if tag not in self.VOID:
            self.stack.append((tag,key))
        if key: self.fields.setdefault(key,[])
    def handle_endtag(self,tag):
        for i in range(len(self.stack)-1,-1,-1):
            if self.stack[i][0]==tag:
                del self.stack[i:]
                break
    def handle_data(self,data):
        if any(tag in {"script","style","noscript","template"} for tag,_ in self.stack): return
        for _,key in self.stack:
            if key: self.fields[key].append(data)
    def text(self,key):
        return norm(" ".join(self.fields.get(key,[])))


def parse_fca(body):
    parser=ScopedHTML();parser.feed(body);parser.close()
    clone=parser.text("section-clone-firm-details")
    genuine=parser.text("section-fca-authorised-firm-details")
    if parser.text("h1")!="IPO Horizon (Clone of FCA authorised firm)":
        raise ValueError("FCA warning title is missing or changed")
    if NO_CONNECTION not in genuine:
        raise ValueError("FCA explicit no-connection evidence is unavailable")
    def field(text,label,next_labels):
        ending="|".join(re.escape(x)+":" for x in next_labels)
        match=re.search(re.escape(label)+r":\s*(.*?)(?=\s+(?:"+ending+r")|$)",text)
        if not match or not match[1].strip(): raise ValueError("FCA field missing: "+label)
        return match[1].strip()
    legal_name=field(genuine,"Firm Name",["Firm Reference Number"])
    frn=field(genuine,"Firm Reference Number",["Address"])
    if legal_name!=FIRM or not re.fullmatch(r"\d{6}",frn): raise ValueError("Unexpected genuine firm record identity")
    clone_name=field(clone,"Name",["Address"])
    if clone_name!="IPO Horizon (Clone of FCA authorised firm)": raise ValueError("Clone section identity differs from warning title")
    def contacts(text):
        return {"website":field(text,"Website",["unused"]).split(" Scammers may")[0],
                "telephone":field(text,"Telephone",["Email","Website"]),
                "address":field(text,"Address",["Telephone","Email","Website"])}
    return {"clone_name":field(clone,"Name",["Address"]),"genuine_name":legal_name,"frn":frn,
            "clone_contacts":contacts(clone),"genuine_contacts":contacts(genuine),
            "exact_evidence":{"clone_section":clone,"genuine_section":genuine,"no_connection_quote":NO_CONNECTION},
            "email_boundary":"Email values are obfuscated in the fetched page; they are not decoded or compared in V1."}


def parse_company(body):
    parser=ScopedHTML();parser.feed(body);parser.close()
    name=parser.text("h1")
    number=parser.text("company-number")
    status=parser.text("company-status")
    if name.casefold()!=FIRM.casefold() or number!="Company number "+COMPANY_NUMBER or not status:
        raise ValueError("Companies House record identity/status selector is missing or changed")
    return {"legal_name":name,"company_number":COMPANY_NUMBER,"status":status,
            "exact_evidence":{"h1":name,"company-number":number,"company-status":status}}


class PublicRecordVerifier:
    def __init__(self,url,method,parser,timeout=15):
        self.url,self.method,self.parser,self.timeout=url,method,parser,timeout
    def verify(self,ident):
        start=time.perf_counter();raw={};observations={};error=None;state=State.NO_DATA
        source={"url":self.url,"origin":"live_https","retrieved_at_utc":datetime.now(timezone.utc).isoformat(),
                "lookup_mode":"curated_public_record","live_register_permissions_lookup":False}
        try:
            raw,_=fetch_policy(self.url,{urlsplit(self.url).hostname},self.timeout)
            if raw.get("error") or raw.get("http_status")!=200 or raw.get("response_truncated"):
                raise ValueError("Authoritative record fetch failed: "+str(raw.get("error") or raw.get("http_status")))
            body=base64.b64decode(raw["raw_body_base64"],validate=True)
            if sha256(body)!=raw.get("captured_sha256") or body.decode("utf-8",errors="replace")!=raw.get("raw_body"):
                raise ValueError("Public source bytes, text and hash differ")
            source["body_sha256"]=raw.get("captured_sha256")
            observations=self.parser(raw["raw_body"])
            state=State.VERIFIED
        except Exception as exc: error={"type":type(exc).__name__,"message":str(exc)}
        limitations=("A public record establishes only its stated facts; it does not authenticate the contacting person.",
                     "FCA warning lookup is a curated public regulator record, not a general live permissions/register API." if self.method=="regulator_record_lookup" else "Companies House active status is registry evidence, not FCA authorisation, investment safety or verification of all filed facts.",
                     "Parser changes, blocked HTTP and missing fields fail visibly; there is no cached-success fallback.")
        group="eg_"+sha256((self.method+":"+self.url).encode())[:24]
        return Evidence(ident,self.method,state,raw,source,observations,limitations,round((time.perf_counter()-start)*1000,3),error,group)


class RegulatorVerifier(PublicRecordVerifier):
    def __init__(self,timeout=15): super().__init__(FCA_URL,"regulator_record_lookup",parse_fca,timeout)


class LegalEntityVerifier(PublicRecordVerifier):
    def __init__(self,timeout=15): super().__init__(CH_URL,"legal_entity_registry",parse_company,timeout)


def website_domain(value):
    # Only remove the literal www. host presentation prefix. No broad subdomain matches.
    from rdap_domain_provenance import domain_name
    host=urlsplit(value if "://" in value else "https://"+value).hostname
    host=domain_name(host or "")
    return host[4:] if host.startswith("www.") else host


def compare_contacts(domain,phone,record,ident):
    started=time.perf_counter();state=State.NO_DATA;observations={};error=None
    if record.evidence_state!=State.VERIFIED:
        error={"type":"RegulatorUnavailable","message":"No validated regulator contact record"}
    else:
        genuine=record.observations["genuine_contacts"]
        canonical=website_domain(genuine["website"])
        domain_match=website_domain(domain)==canonical
        # Preserve international prefixes exactly; remove visual spaces/punctuation only.
        phone_match=re.sub(r"[\s()-]","",phone)==re.sub(r"[\s()-]","",genuine["telephone"]) if phone else None
        observations={"supplied_domain":domain,"regulator_domain":canonical,"domain_match":domain_match,
                      "supplied_phone":phone,"regulator_phone":genuine["telephone"],"phone_match":phone_match,
                      "exact_evidence":record.observations["exact_evidence"]["genuine_section"]}
        state=State.CONSISTENT if domain_match and phone_match is not False else State.CONTRADICTED
    return Evidence(ident,"regulator_contact_comparison",state,{"comparison":observations},
                    {"url":record.source_provenance["url"],"parent_evidence_id":record.id,"origin":"derived_exact_comparison"},
                    observations,("A mismatch means these contacts differ from the regulator-published genuine record; a match does not authenticate the caller.",),
                    round((time.perf_counter()-started)*1000,3),error,record.evidence_group_id)
