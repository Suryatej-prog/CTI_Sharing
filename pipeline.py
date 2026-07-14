import os
import json
from datetime import datetime
from transformers import pipeline
from neo4j import GraphDatabase

# 1. Database Credentials Configuration
NEO4J_URI = "bolt://10.2.2.132:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "ABCDEFGHI"

neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# 2. Load Local MITRE Dictionary
MITRE_LOOKUP_PATH = "mitre_lookup.json"
try:
    with open(MITRE_LOOKUP_PATH, "r") as f:
        mitre_db = json.load(f)
    print("Local MITRE ATT&CK Dictionary loaded successfully!")
except Exception as e:
    print(f"Warning: Could not load mitre_lookup.json ({e}). Using empty dictionary.")
    mitre_db = {}

print("Loading Cybersecurity BERT model into memory...")

bert_ner = pipeline(
    task="token-classification",
    model="attack-vector/SecureModernBERT-NER",
    tokenizer="attack-vector/SecureModernBERT-NER",
    aggregation_strategy="simple"
)

print("BERT Model Loaded successfully!")


def normalize_entity(name: str, entity_type: str) -> str:
    cleaned = name.strip().upper()
    cleaned = cleaned.replace("-", "").replace(" ", "")
    aliases = {
        "NOBELIUM": "APT29",
        "COBALTSTRIKEBEACON": "COBALTSTRIKE",
        "PAYLOADEXE": "PAYLOAD.EXE"
    }
    return aliases.get(cleaned, name.strip())


def determine_relationship(source_type: str, target_type: str) -> str:
    pair = (source_type.upper(), target_type.upper())
    mapping = {
        ("THREATACTOR", "MALWARE"): "UTILIZES",
        ("MALWARE", "VULNERABILITY"): "EXPLOITS",
        ("MALWARE", "HOST"): "TARGETS",
        ("VULNERABILITY", "HOST"): "AFFECTS",
        ("MALWARE", "DOMAIN"): "COMMUNICATES_WITH",
        ("MALWARE", "IPADDRESS"): "COMMUNICATES_WITH",
        ("THREATACTOR", "HOST"): "TARGETS"
    }
    return mapping.get(pair, "ASSOCIATED_WITH")


def enrich_with_mitre(session, node_name, node_type, file_name):
    lookup_key = node_name.lower().strip()
    matched_tech = None
    for key, data in mitre_db.items():
        if key in lookup_key or lookup_key in key:
            matched_tech = data
            break

    if matched_tech:
        print(f"MITRE Match Found: '{node_name}' mapped to {matched_tech['technique_id']} ({matched_tech['technique_name']})")
        mitre_query = f"""
        MATCH (node:`{node_type}` {{name: $node_name}})
        MERGE (m:MitreTechnique {{id: $tech_id}})
        SET m.name = $tech_name, m.tactic = $tactic
        MERGE (node)-[:MAPS_TO_TTP]->(m)
        """
        session.run(mitre_query,
                    node_name=node_name,
                    tech_id=matched_tech['technique_id'],
                    tech_name=matched_tech['technique_name'],
                    tactic=matched_tech['tactic'])


def run_bert_graph_pipeline(file_path: str, ipfs_cid: str = "", report_name: str = ""):
    file_name = report_name if report_name else os.path.basename(file_path)
    timestamp = datetime.utcnow().isoformat()

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        text_content = f.read()

    print(f"\n--- STEP 1: Running BERT Token Extraction on {file_name} ---")
    ner_results = bert_ner(text_content)

    if not ner_results:
        print("No cybersecurity entities detected in this file.")
        return

    print(f"BERT found {len(ner_results)} general entities.")
    print(f"\n--- STEP 2: Writing Directly to Neo4j Graph ---")

    with neo4j_driver.session() as session:

        # A. Create the parent tracking Report Node with IPFS CID
        session.run(
            "MERGE (r:Report {name: $report_name}) SET r.ipfs_cid = $ipfs_cid, r.timestamp = $timestamp",
            report_name=file_name,
            ipfs_cid=ipfs_cid,
            timestamp=timestamp
        )

        previous_node = None

        for entity in ner_results:
            entity_type = entity['entity_group'].replace("-", "").title()
            entity_name = normalize_entity(entity['word'].strip(), entity_type)

            if not entity_name:
                continue

            # 1. Insert node into Neo4j
            node_query = f"""
            MERGE (node:`{entity_type}` {{name: $name}})
            WITH node
            MATCH (rep:Report {{name: $report_name}})
            MERGE (node)-[:FOUND_IN]->(rep)
            RETURN node
            """
            node_params = {
                "name": entity_name,
                "report_name": file_name
            }
            session.run(node_query, node_params)

            # 2. MITRE ATT&CK enrichment
            enrich_with_mitre(session, entity_name, entity_type, file_name)

            # 3. Sequential Chain Creation with Explainable Provenance
            if previous_node:
                relationship = determine_relationship(previous_node['type'], entity_type)

                link_query = f"""
                MATCH (source:`{previous_node['type']}` {{name: $source_name}})
                MATCH (target:`{entity_type}` {{name: $target_name}})
                MERGE (source)-[rel:{relationship}]->(target)
                SET rel.source_report = $source_report,
                    rel.timestamp = $timestamp,
                    rel.ipfs_cid = $ipfs_cid,
                    rel.confidence = $confidence
                """
                link_params = {
                    "source_name": previous_node['name'],
                    "target_name": entity_name,
                    "source_report": file_name,
                    "timestamp": timestamp,
                    "ipfs_cid": ipfs_cid,
                    "confidence": round(float(entity.get('score', 0.0)), 4)
                }
                session.run(link_query, link_params)

            previous_node = {"name": entity_name, "type": entity_type}

    print("Success! Graph populated with BERT extraction, MITRE mapping, and provenance metadata.")


if __name__ == "__main__":
    run_bert_graph_pipeline("C:\\Users\\tanish\\CCN\\report6.txt")