"""
cti_pipeline.py  (unified, any-file-in / clean-graph-out)
Author: Tanish Jaladanki<PES2UG24CS549

ONE pipeline that accepts pretty much ANY CTI document and builds a clean
knowledge graph from it. Input type is auto-detected.

Optimizations included:
- Dynamic relative pathing (OS agnostic).
- Hugging Face Batched GPU inference.
- Multi-threaded Async Queue (GPU extracts while CPU handles network).
- Cypher UNWIND batched transactions for massive database speedups.
- Universal Document Parsers (PDF, DOCX, HTML, CSV, generic text).
"""

import os
import json
import re
import csv
import time
import queue
import threading
from collections import defaultdict
from neo4j import GraphDatabase

# --- 1. Dynamic Paths & Database Credentials ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

NEO4J_URI = "neo4j://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "12345678"  # Verify this matches your local Windows DB

neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# --- 2. Load Local MITRE Dictionary ---
MITRE_LOOKUP_PATH = os.path.join(BASE_DIR, "mitre_lookup.json")
try:
    with open(MITRE_LOOKUP_PATH, "r") as f:
        mitre_db = json.load(f)
    print("✅ Local MITRE ATT&CK Dictionary loaded successfully!")
except Exception as e:
    print(f"⚠️ Warning: Could not load mitre_lookup.json locally. Using empty dictionary.")
    mitre_db = {}

# Lazy model loading variables
_bert_ner = None
_tokenizer = None
MODEL_NAME = "attack-vector/SecureModernBERT-NER"
MAX_TOKENS_PER_SENTENCE = 450


def _get_model():
    global _bert_ner, _tokenizer
    if _bert_ner is None:
        import torch
        from transformers import pipeline, AutoTokenizer
        print("Loading Cybersecurity BERT model into memory...")
        
        device = 0 if torch.cuda.is_available() else -1
        if device == 0:
            print("🚀 CUDA GPU detected! Running model on GPU.")
        else:
            print("⚠️ CUDA GPU not found. Falling back to CPU.")

        # Ignore BPE tokenization spaces warning natively
        _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, clean_up_tokenization_spaces=False)
        _bert_ner = pipeline(
            task="token-classification",
            model=MODEL_NAME,
            tokenizer=_tokenizer,
            aggregation_strategy="simple",
            device=device
        )
        print("✅ BERT Model Successfully Initialized!")
    return _bert_ner, _tokenizer

# ---------------------------------------------------------------------------
# Canonical Vocabularies
# ---------------------------------------------------------------------------

TYPE_MAP = {
    "HackOrg": "ThreatActor", "Tool": "Malware", "Area": "Location",
    "OffAct": "Attack", "Idus": "Industry", "Time": "Time",
    "SamFile": "File", "Org": "Organization", "Exp": "Vulnerability",
    "SecTeam": "SecurityTeam", "Way": "Technique", "Features": "Feature",
    "Purp": "Purpose",
}

REL_MAP = {
    ("ThreatActor", "Malware"): "UTILIZES",
    ("ThreatActor", "Technique"): "USES_TECHNIQUE",
    ("ThreatActor", "Organization"): "TARGETS",
    ("ThreatActor", "Location"): "OPERATES_IN",
    ("ThreatActor", "Industry"): "TARGETS_INDUSTRY",
    ("ThreatActor", "Host"): "TARGETS",
    ("Malware", "Vulnerability"): "EXPLOITS",
    ("Malware", "Organization"): "TARGETS",
    ("Malware", "File"): "DROPS",
    ("Malware", "Technique"): "IMPLEMENTS",
    ("Malware", "Host"): "TARGETS",
    ("Malware", "Domain"): "COMMUNICATES_WITH",
    ("Malware", "IPAddress"): "COMMUNICATES_WITH",
    ("Vulnerability", "Organization"): "AFFECTS",
    ("Vulnerability", "Host"): "AFFECTS",
    ("SecurityTeam", "ThreatActor"): "ATTRIBUTES",
    ("SecurityTeam", "Malware"): "ANALYZES",
}

def determine_relationship(source_type: str, target_type: str):
    if (source_type, target_type) in REL_MAP:
        return REL_MAP[(source_type, target_type)], False
    if (target_type, source_type) in REL_MAP:
        return REL_MAP[(target_type, source_type)], True
    return "ASSOCIATED_WITH", False

def normalize_entity(name: str) -> str:
    return " ".join(name.strip().split())

def canonicalize_label(label: str) -> str:
    cleaned = re.sub(r"[-_]+", " ", label.strip())
    return "".join(word.capitalize() for word in cleaned.split())

# ---------------------------------------------------------------------------
# Input Type Detection
# ---------------------------------------------------------------------------

def detect_input_type(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".jsonl": return "jsonl"
    if ext == ".json":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "techniques" in data:
                return "navigator_json"
        except Exception: pass
        return "generic_json"
    if ext in (".html", ".htm"): return "html"
    if ext == ".pdf": return "pdf"
    if ext == ".docx": return "docx"
    if ext == ".csv": return "csv"
    
    bio_tag_re = re.compile(r"^(O|[BI]-\w+)$")
    checked, bio_like = 0, 0
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split()
            if not parts: continue
            checked += 1
            if len(parts) == 2 and bio_tag_re.match(parts[1]): bio_like += 1
            if checked >= 30: break
    if checked > 0 and bio_like / checked >= 0.9: return "gold_bio"
    return "raw_text"

def detect_jsonl_subtype(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: record = json.loads(line)
            except json.JSONDecodeError: continue
            if not isinstance(record, dict): continue

            if "tokens" in record and isinstance(record["tokens"], list):
                tag_key = next((k for k in ("ner_tags", "labels", "tags") if k in record), None)
                if tag_key and isinstance(record[tag_key], list):
                    return "jsonl_bio"

            if "text" in record and isinstance(record["text"], str) and "entities" in record and isinstance(record["entities"], list):
                return "jsonl_gold_spans" if _looks_like_gold_span_file(file_path) else "jsonl_prose"

            return "jsonl_prose"
    return "jsonl_prose"

def _looks_like_gold_span_file(file_path: str, sample_size: int = 20) -> bool:
    checked, matches = 0, 0
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: record = json.loads(line)
            except json.JSONDecodeError: continue
            if not isinstance(record, dict): continue
            checked += 1
            if "text" in record and isinstance(record["text"], str) and "entities" in record and isinstance(record["entities"], list):
                if not record["entities"] or all(isinstance(e, dict) and "start_offset" in e and "end_offset" in e and "label" in e for e in record["entities"]):
                    matches += 1
            if checked >= sample_size: break
    return checked > 0 and matches / checked >= 0.8

# ---------------------------------------------------------------------------
# Document Extractors
# ---------------------------------------------------------------------------

def extract_navigator_text(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as f: data = json.load(f)
    comments = [t["comment"] for t in data.get("techniques", []) if "comment" in t]
    cleaned = []
    for c in comments:
        c = re.sub(r"\[([^\]]+)\]\(https?://[^\)]+\)", r"\1", c)
        c = re.sub(r"\(Citation:[^)]+\)", "", c)
        if c.strip(): cleaned.append(" ".join(c.split()))
    return " ".join(cleaned)

def extract_generic_json_text(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as f: data = json.load(f)
    texts = []
    def walk(obj):
        if isinstance(obj, dict):
            for v in obj.values(): walk(v)
        elif isinstance(obj, list):
            for v in obj: walk(v)
        elif isinstance(obj, str):
            if len(obj) > 20 and " " in obj: texts.append(obj)
    walk(data)
    return " ".join(texts)

def extract_html_text(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f: html = f.read()
    html = re.sub(r"(?is)<(script|style|nav|footer|header)\b.*?>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    text = text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
    return re.sub(r"&#\d+;", " ", text)

def extract_pdf_text(file_path: str) -> str:
    try:
        import pdfplumber
    except ImportError:
        print("⚠️ pdfplumber missing. Install: pip install pdfplumber")
        return ""
    parts = []
    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text: parts.append(page_text)
    return "\n".join(parts)

def extract_docx_text(file_path: str) -> str:
    try:
        import docx
    except ImportError:
        print("⚠️ python-docx missing. Install: pip install python-docx")
        return ""
    document = docx.Document(file_path)
    return "\n".join(p.text for p in document.paragraphs)

def extract_csv_text(file_path: str) -> str:
    extracted_texts = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            sample = f.read(2048)
            f.seek(0)
            dialect = csv.Sniffer().sniff(sample) if sample else csv.excel
            reader = csv.reader(f, dialect)
            headers = next(reader, None)
            if not headers: return ""
            target_indices = [i for i, h in enumerate(headers) if any(kw in h.lower().strip() for kw in ["text", "desc", "comment", "body", "summary", "content"])]
            fallback = len(target_indices) == 0
            for row in reader:
                if fallback:
                    for cell in row:
                        if len(cell) > 15 and " " in cell: extracted_texts.append(cell)
                else:
                    for idx in target_indices:
                        if idx < len(row) and row[idx].strip(): extracted_texts.append(row[idx])
    except Exception as e: print(f"⚠️ Error reading CSV: {e}")
    return " ".join(extracted_texts)

def load_and_clean_document(file_path: str, input_type: str) -> str:
    if input_type == "navigator_json": raw = extract_navigator_text(file_path)
    elif input_type == "generic_json": raw = extract_generic_json_text(file_path)
    elif input_type == "html": raw = extract_html_text(file_path)
    elif input_type == "pdf": raw = extract_pdf_text(file_path)
    elif input_type == "docx": raw = extract_docx_text(file_path)
    elif input_type == "csv": raw = extract_csv_text(file_path)
    else: 
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f: raw = f.read()
    return clean_raw_text(raw)

def clean_raw_text(text: str) -> str:
    if not text: return ""
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"(?m)^#{1,6}\s*", "", text)
    text = re.sub(r"(?m)^[ \t]*[-*•‣▪]\s+", "", text)
    text = re.sub(r"(?m)^[ \t]*\d+[\.\)]\s+", "", text)
    text = re.sub(r"\[\d+\]", "", text)
    text = re.sub(r"\[citation needed\]", "", text, flags=re.IGNORECASE)
    text = re.sub(r"https?://\S+", "", text)
    text = re.sub(r"(?im)^\s*page\s+\d+(\s*of\s*\d+)?\s*$", "", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return " ".join(text.split()).strip()

# ---------------------------------------------------------------------------
# Parsers & GPU Processing Functions
# ---------------------------------------------------------------------------

def entities_from_char_span_record(text: str, entities: list):
    results = []
    for ent in entities:
        try:
            start, end = ent["start_offset"], ent["end_offset"]
            span_text = normalize_entity(text[start:end]).strip(" \t\n,.;:!?\"'()[]{}")
            if not span_text or len(span_text) < 2: continue
            canon_type = canonicalize_label(ent["label"])
            results.append((span_text, canon_type))
        except (KeyError, IndexError, TypeError): continue
    return results

def entities_from_token_tag_record(tokens, tags):
    entities = []
    i = 0
    while i < len(tokens):
        tag = tags[i]
        if isinstance(tag, str) and tag.startswith("B-"):
            etype = tag[2:]
            words = [tokens[i]]
            j = i + 1
            while j < len(tokens) and tags[j] == "I-" + etype:
                words.append(tokens[j])
                j += 1
            text = normalize_entity(" ".join(str(w) for w in words))
            canon_type = TYPE_MAP.get(etype, canonicalize_label(etype))
            entities.append((text, canon_type))
            i = j
        else: i += 1
    return entities

def split_into_sentences(text: str):
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return [s for s in sentences if s]

def chunk_text(text: str, max_tokens: int = MAX_TOKENS_PER_SENTENCE):
    _, tokenizer = _get_model()
    sentences = split_into_sentences(text)
    units = []
    for sent in sentences:
        ids = tokenizer.encode(sent, add_special_tokens=False, verbose=False)
        if len(ids) > max_tokens:
            for i in range(0, len(ids), max_tokens):
                units.append(tokenizer.decode(ids[i:i + max_tokens]))
        else: units.append(sent)
    return units

def sentence_units_from_ner(text: str):
    bert_ner, _ = _get_model()
    chunks = chunk_text(text)
    if not chunks: return
        
    ner_results_batch = bert_ner(chunks, batch_size=128)
    if isinstance(ner_results_batch, dict) or (len(ner_results_batch) > 0 and isinstance(ner_results_batch[0], str)):
        ner_results_batch = [ner_results_batch]

    for ner_results in ner_results_batch:
        entities = []
        for entity in ner_results:
            raw_type = entity["entity_group"].replace("-", "").title()
            raw_name = entity["word"]
            entity_name = normalize_entity(raw_name)
            if not entity_name or len(entity_name) < 2: continue
            canon_type = TYPE_MAP.get(raw_type, raw_type)
            entities.append((entity_name, canon_type))
        yield entities

def find_mitre_match(node_name):
    lookup_key = node_name.lower().strip()
    for key, data in mitre_db.items():
        if key in lookup_key or lookup_key in key: return data
    return None

# ---------------------------------------------------------------------------
# High-Speed Queue Manager Helper
# ---------------------------------------------------------------------------

def enqueue_entities(sentence_entity_lists, file_name, ipfs_cid, enable_mitre, extraction_queue, record_idx=None):
    """Processes extracted entities and queues them for the database thread."""
    MAX_ENTITIES_FOR_FULL_PAIRING = 12 

    for entities in sentence_entity_lists:
        uniq = list({(t, e) for t, e in entities})
        payload = {"nodes": [], "edges": []}

        # 1. Package Nodes
        for entity_name, entity_type in uniq:
            node_data = {
                "name": entity_name, "type": entity_type,
                "report_name": file_name, "cid": ipfs_cid
            }
            if enable_mitre:
                mitre_info = find_mitre_match(entity_name)
                if mitre_info:
                    node_data.update({
                        "mitre_id": mitre_info["technique_id"],
                        "mitre_name": mitre_info["technique_name"],
                        "mitre_tactic": mitre_info["tactic"]
                    })
            payload["nodes"].append(node_data)

        # 2. Package Edges (with Hub and Spoke fallback for explosive arrays)
        if len(uniq) > MAX_ENTITIES_FOR_FULL_PAIRING:
            idx_str = f" (record {record_idx})" if record_idx else ""
            print(f"   ⚠️ Entity burst ({len(uniq)} entities) exceeds pairing cap -- using hub-and-spoke{idx_str}.")
            pairs = [(uniq[0], other) for other in uniq[1:]]
        else:
            pairs = [(uniq[a], uniq[b]) for a in range(len(uniq)) for b in range(a + 1, len(uniq))]

        for (a_name, a_type), (b_name, b_type) in pairs:
            rel_label, swapped = determine_relationship(a_type, b_type)
            src_name, src_type = (b_name, b_type) if swapped else (a_name, a_type)
            tgt_name, tgt_type = (a_name, a_type) if swapped else (b_name, b_type)

            payload["edges"].append({
                "src_name": src_name, "src_type": src_type,
                "tgt_name": tgt_name, "tgt_type": tgt_type,
                "rel_label": rel_label,
                "report_name": file_name, "cid": ipfs_cid
            })

        extraction_queue.put(payload)

# ---------------------------------------------------------------------------
# Database Background Thread
# ---------------------------------------------------------------------------

def cpu_db_consumer(extraction_queue, driver):
    nodes_by_type = defaultdict(list)
    edges_by_type = defaultdict(list)
    batch_size = 0
    MAX_BATCH = 250

    def flush_to_db(session):
        nonlocal batch_size
        
        for n_type, n_data in nodes_by_type.items():
            query = f"""
            UNWIND $batch AS item
            MERGE (node:`{n_type}` {{name: item.name}})
            WITH node, item
            MATCH (rep:Report {{name: item.report_name}})
            MERGE (node)-[rel:FOUND_IN]->(rep)
            SET rel.ipfs_cid = item.cid, rel.timestamp = datetime()
            """
            session.run(query, batch=n_data)
            
            mitre_data = [item for item in n_data if item.get("mitre_id")]
            if mitre_data:
                session.run(f"""
                UNWIND $batch AS item
                MATCH (node:`{n_type}` {{name: item.name}})
                MERGE (m:MitreTechnique {{id: item.mitre_id}})
                SET m.name = item.mitre_name, m.tactic = item.mitre_tactic
                MERGE (node)-[:MAPS_TO_TTP]->(m)
                """, batch=mitre_data)

        for e_key, e_data in edges_by_type.items():
            src_type, rel_label, tgt_type = e_key
            query = f"""
            UNWIND $batch AS item
            MATCH (source:`{src_type}` {{name: item.src_name}})
            MATCH (target:`{tgt_type}` {{name: item.tgt_name}})
            MERGE (source)-[rel:`{rel_label}`]->(target)
            SET rel.source_report = item.report_name, rel.ipfs_cid = item.cid
            """
            session.run(query, batch=e_data)

        nodes_by_type.clear()
        edges_by_type.clear()
        batch_size = 0

    with driver.session() as session:
        while True:
            payload = extraction_queue.get()
            if payload is None:
                if batch_size > 0: flush_to_db(session)
                extraction_queue.task_done()
                break

            for n in payload.get("nodes", []):
                nodes_by_type[n["type"]].append(n)
                batch_size += 1
                
            for e in payload.get("edges", []):
                e_key = (e["src_type"], e["rel_label"], e["tgt_type"])
                edges_by_type[e_key].append(e)
                batch_size += 1

            if batch_size >= MAX_BATCH: flush_to_db(session)
            extraction_queue.task_done()

# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

def run_pipeline(file_path: str, ipfs_cid: str = "PENDING_BLOCKCHAIN_SYNC", enable_mitre: bool = False):
    file_name = os.path.basename(file_path)
    if not os.path.exists(file_path):
        print(f"❌ Error: File {file_path} not found.")
        return

    input_type = detect_input_type(file_path)
    print(f"\n--- Phase 0: Detected input type for [{file_name}]: {input_type} ---")

    jsonl_subtype = detect_jsonl_subtype(file_path) if input_type == "jsonl" else None
    
    # Load model only if needed (Standard files and jsonl_prose need it, Gold files do not)
    if input_type != "gold_bio" and jsonl_subtype != "jsonl_bio" and jsonl_subtype != "jsonl_gold_spans":
        _get_model()

    with neo4j_driver.session() as session:
        session.run("MERGE (r:Report {name: $report_name}) SET r.ipfs_cid = $cid", 
                    report_name=file_name, cid=ipfs_cid)

    extraction_queue = queue.Queue(maxsize=1000)
    cpu_thread = threading.Thread(target=cpu_db_consumer, args=(extraction_queue, neo4j_driver), daemon=True)
    cpu_thread.start()

    print(f"\n--- Phase 1/2: Asynchronous Streaming Extraction (GPU) + Insertion (CPU) ---")
    start_time = time.time()

    if input_type == "jsonl":
        print(f"   Detected JSONL subtype: {jsonl_subtype}")
        line_idx = 0
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip(): continue
                try: line_data = json.loads(line)
                except json.JSONDecodeError: continue

                sentence_entity_lists = []

                if jsonl_subtype == "jsonl_bio":
                    tokens = line_data.get("tokens")
                    tag_key = next((k for k in ("ner_tags", "labels", "tags") if k in line_data), None)
                    if tokens and tag_key:
                        entities = entities_from_token_tag_record(tokens, line_data[tag_key])
                        if entities: sentence_entity_lists.append(entities)

                elif jsonl_subtype == "jsonl_gold_spans":
                    text = line_data.get("text", "")
                    raw_entities = line_data.get("entities", [])
                    if text and raw_entities:
                        entities = entities_from_char_span_record(text, raw_entities)
                        if entities: sentence_entity_lists.append(entities)

                else:  # jsonl_prose
                    snippet_found = False
                    for field in ["text", "comment", "body", "description"]:
                        if field in line_data and isinstance(line_data[field], str):
                            clean_snippet = clean_raw_text(line_data[field])
                            if clean_snippet:
                                snippet_found = True
                                for entities in sentence_units_from_ner(clean_snippet):
                                    if entities: sentence_entity_lists.append(entities)
                    
                    if not snippet_found:
                        string_values = [v for v in line_data.values() if isinstance(v, str) and len(v) > 20]
                        if string_values:
                            clean_snippet = clean_raw_text(max(string_values, key=len))
                            if clean_snippet:
                                for entities in sentence_units_from_ner(clean_snippet):
                                    if entities: sentence_entity_lists.append(entities)

                # Send lists to Queue Helper
                enqueue_entities(sentence_entity_lists, file_name, ipfs_cid, enable_mitre, extraction_queue, line_idx)

                line_idx += 1
                if line_idx % 100 == 0:
                    print(f"   📈 Progress Update: processed {line_idx} records...")

    else:
        print(f"   Extracting and cleaning legacy document standard ({input_type})...")
        
        # 1. Dynamically parse document based on file type
        text = load_and_clean_document(file_path, input_type)
        
        if not text.strip() and input_type != "gold_bio":
            print("   ⚠️ No text could be extracted from the document.")
        else:
            sentence_entity_lists = []
            
            # 2. Extract Entities
            if input_type == "gold_bio":
                # Fallback for old pure-text Gold files
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                lines = content.replace("\r\n", "\n").split("\n")
                sentence = []
                for line in lines:
                    line = line.strip()
                    if not line:
                        if sentence:
                            tokens = [p[0] for p in sentence]
                            tags = [p[1] for p in sentence]
                            entities = entities_from_token_tag_record(tokens, tags)
                            if entities: sentence_entity_lists.append(entities)
                            sentence = []
                        continue
                    parts = line.split()
                    if len(parts) == 2: sentence.append((parts[0], parts[1]))
            else:
                for entities in sentence_units_from_ner(text):
                    if entities: sentence_entity_lists.append(entities)
            
            # 3. Send lists to Queue Helper
            enqueue_entities(sentence_entity_lists, file_name, ipfs_cid, enable_mitre, extraction_queue)
            print(f"   📈 Progress Update: Document extracted and queued.")

    # Shutdown sequence
    print("\n[Tasks Completed] Telling CPU to flush remaining queue items to database...")
    extraction_queue.put(None) 
    cpu_thread.join()
    neo4j_driver.close()
    
    print(f"✅ Pipeline executed seamlessly in {time.time() - start_time:.2f} seconds!")


if __name__ == "__main__":
    dataset_path = os.path.join(BASE_DIR, "train.txt")
    
    run_pipeline(
        file_path=dataset_path,
        ipfs_cid="QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco",
        enable_mitre=False,
    )
