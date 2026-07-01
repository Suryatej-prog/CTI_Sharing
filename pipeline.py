import os
from google import genai
from google.genai import types
from neo4j import GraphDatabase
from schema import ThreatIntelReport

# Credentials Configuration
MY_API_KEY = "AQ.Ab8RN6ImQOcLXd27kkPmuI-3-8chFcXWjxIyRcWObWK1M-rBwQ"
NEO4J_URI = "neo4j://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "12345678"

# Setup Clients
client = genai.Client(api_key=MY_API_KEY)
neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def run_master_pipeline(file_path: str):
    print(f"\n--- STEP 1: Uploading & Parsing Document via Gemini Flash ---")
    uploaded_file = client.files.upload(file=file_path)
    
    system_instruction = (
        "You are an expert Cyber Threat Intelligence (CTI) analyst. Your task is to extract "
        "structural threat intelligence relationships (triples) from the attached unstructured report file. "
        "Map entities strictly to cybersecurity concepts like Threat Actor, Malware, Vulnerability, "
        "IP Address, Registry Key, File, or Host. Normalize relationship verbs to uppercase terms."
    )

    response = client.models.generate_content(
        model='gemini-2.5-flash', 
        contents=[uploaded_file, "Extract all threat intelligence triples from this document."],
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=ThreatIntelReport,
            temperature=0.1 
        ),
    )
    client.files.delete(name=uploaded_file.name)
    
    # Validated Object
    report_data = ThreatIntelReport.model_validate_json(response.text)
    print(f"✅ Extracted {len(report_data.triples)} structural security definitions!")

    print(f"\n--- STEP 2: Writing Directly to Neo4j Graph (Connected Architecture) ---")
    
    file_name = os.path.basename(file_path)
    
    with neo4j_driver.session() as session:
        # A. First, guarantee the unique central Report node exists 
        session.run(
            "MERGE (r:Report {name: $report_name})", 
            report_name=file_name
        )
        
        # B. Run explicit sequential bindings for the extraction definitions
        for triple in report_data.triples:
            query = f"""
            // 1. Create or match the specific source and target orbs
            MERGE (source:`{triple.source_type}` {{name: $source_name}})
            MERGE (target:`{triple.target_type}` {{name: $target_name}})
            
            // 2. Clear visual memory context and bind the actual directed line relationship
            WITH source, target
            MERGE (source)-[rel:`{triple.relationship}`]->(target)
            
            // 3. Connect both items explicitly to the original central tracking report file
            WITH source, target
            MATCH (rep:Report {{name: $report_name}})
            MERGE (source)-[:FOUND_IN]->(rep)
            MERGE (target)-[:FOUND_IN]->(rep)
            """
            
            session.run(query, 
                        source_name=triple.source_entity, 
                        target_name=triple.target_entity,
                        report_name=file_name)
            
    print("✅ Success! Connected Database successfully populated.")

if __name__ == "__main__":
    # Test this on any real or fake threat intel text file you created
    run_master_pipeline("C:\\Users\\tanish\CCN\\report3.txt")