import os
from datetime import datetime
from transformers import pipeline
from neo4j import GraphDatabase

# 1. Database Credentials Configuration
NEO4J_URI = "bolt://10.2.2.132:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "ABCDEFGHI"

# Connect to Neo4j
neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

print("Loading Cybersecurity BERT model into memory... (First run may take a moment)")

# Load specialized token-classification pipeline using a cybersecurity BERT framework
bert_ner = pipeline(
    task="token-classification",
    model="attack-vector/SecureModernBERT-NER",
    tokenizer="attack-vector/SecureModernBERT-NER",
    aggregation_strategy="simple"
)

print("BERT Model Loaded successfully!")


def run_bert_graph_pipeline(file_path: str, ipfs_cid: str = ""):
    file_name = os.path.basename(file_path)
    timestamp = datetime.utcnow().isoformat()

    # Read the text file
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

        # B. Dynamically loop over every entity BERT identified
        for entity in ner_results:
            entity_type = entity['entity_group'].replace("-", "").title()
            entity_name = entity['word'].strip()

            if not entity_name:
                continue

            # 1. Insert the node dynamically into Neo4j
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

            # 2. Sequential Chain Creation with Explainable Provenance
            if previous_node:
                link_query = f"""
                MATCH (source:`{previous_node['type']}` {{name: $source_name}})
                MATCH (target:`{entity_type}` {{name: $target_name}})
                MERGE (source)-[rel:ASSOCIATED_WITH]->(target)
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

    print("Success! Graph successfully populated using BERT extraction with provenance metadata.")


if __name__ == "__main__":
    run_bert_graph_pipeline("C:\\Users\\tanish\\CCN\\report6.txt")