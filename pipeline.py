import os
import json
from transformers import pipeline
from neo4j import GraphDatabase

# --- 1. Database Credentials Configuration ---
NEO4J_URI = "URL"  
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "PASSWORD"  # Replace with your active password

neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# --- 2. Load Local MITRE Dictionary ---
MITRE_LOOKUP_PATH = "mitre_lookup.json"
try:
    with open(MITRE_LOOKUP_PATH, "r") as f:
        mitre_db = json.load(f)
    print("✅ Local MITRE ATT&CK Dictionary loaded successfully!")
except Exception as e:
    print(f"⚠️ Warning: Could not load mitre_lookup.json locally ({e}). Using empty dictionary.")
    mitre_db = {}

print("Loading Cybersecurity BERT model into memory...")
bert_ner = pipeline(
    task="token-classification",
    model="attack-vector/SecureModernBERT-NER",
    tokenizer="attack-vector/SecureModernBERT-NER",
    aggregation_strategy="simple"
)
print("✅ BERT Model Successfully Initialized!")


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


# --- NEW FEATURE: MITRE Context Connector ---
def enrich_with_mitre(session, node_name, node_type, file_name):
    """
    Checks if the extracted node matches a known attack technique 
    and automatically attaches a standard MITRE ATT&CK node to it.
    """
    lookup_key = node_name.lower().strip()
    
    # Check for direct or partial matches in the dictionary
    matched_tech = None
    for key, data in mitre_db.items():
        if key in lookup_key or lookup_key in key:
            matched_tech = data
            break
            
    if matched_tech:
        print(f"   🎯 MITRE Match Found: '{node_name}' mapped to {matched_tech['technique_id']} ({matched_tech['technique_name']})")
        
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


def run_bert_graph_pipeline(file_path: str, ipfs_cid: str = "PENDING_BLOCKCHAIN_SYNC"):
    file_name = os.path.basename(file_path)
    
    if not os.path.exists(file_path):
        print(f"❌ Error: File {file_path} not found.")
        return
        
    with open(file_path, "r", encoding="utf-8") as f:
        text_content = f.read()

    print(f"\n--- Phase 1: Contextual Token Extraction on [{file_name}] ---")
    ner_results = bert_ner(text_content)
    
    if not ner_results:
        print("No cyber threat entities identified.")
        return

    print(f"✅ BERT discovered {len(ner_results)} threat components.")

    print(f"\n--- Phase 2: Processing and Dynamic Neo4j Graph Insertion ---")
    with neo4j_driver.session() as session:
        session.run(
            "MERGE (r:Report {name: $report_name}) SET r.ipfs_cid = $cid", 
            report_name=file_name, 
            cid=ipfs_cid
        )
        
        previous_node = None
        
        for entity in ner_results:
            raw_type = entity['entity_group'].replace("-", "").title()
            raw_name = entity['word']
            
            entity_name = normalize_entity(raw_name, raw_type)
            entity_type = raw_type
            
            if not entity_name or len(entity_name) < 2:
                continue

            # 1. Insert/Merge Entity Node
            node_query = f"""
            MERGE (node:`{entity_type}` {{name: $name}})
            WITH node
            MATCH (rep:Report {{name: $report_name}})
            MERGE (node)-[rel:FOUND_IN]->(rep)
            SET rel.ipfs_cid = $cid, rel.timestamp = datetime()
            RETURN node
            """
            
            node_params = {
                "name": entity_name,
                "report_name": file_name,
                "cid": ipfs_cid
            }
            session.run(node_query, node_params)
            
            # --- Fire MITRE enrichment validation logic ---
            enrich_with_mitre(session, entity_name, entity_type, file_name)
            
            # 2. Sequential/Semantic Chain Connection
            if previous_node:
                rel_label = determine_relationship(previous_node['type'], entity_type)
                
                link_query = f"""
                MATCH (source:`{previous_node['type']}` {{name: $source_name}})
                MATCH (target:`{entity_type}` {{name: $target_name}})
                MERGE (source)-[rel:`{rel_label}`]->(target)
                SET rel.source_report = $report_name, rel.ipfs_cid = $cid
                """
                
                link_params = {
                    "source_name": previous_node['name'],
                    "target_name": entity_name,
                    "report_name": file_name,
                    "cid": ipfs_cid
                }
                session.run(link_query, link_params)
            
            previous_node = {"name": entity_name, "type": entity_type}
            
    print(f"✅ Success! Graph data layer completely built for {file_name}.")


if __name__ == "__main__":
    # Test execution using report 7 which contains a 'credential stuffing' attack vector
    run_bert_graph_pipeline("C:\\Users\\tanish\\CCN\\dataset\\train.txt", ipfs_cid="QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco")
