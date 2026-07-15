import json
import requests
from neo4j import GraphDatabase

# --- 1. Configurations ---
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3:8b"  # Change to "qwen2.5:3b" or "phi3" if running on lower specs

NEO4J_URI = "neo4j://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "12345678"  # Replace with your active password

# --- 2. The Strict System Schema Context Prompt ---
SYSTEM_PROMPT = """
You are an expert Text-to-Cypher translation engine. Your sole job is to convert natural language English questions into syntactically perfect Neo4j Cypher queries based ONLY on the schema provided below.

=== DATABASE SCHEMA CONTRACT ===
1. Labels (Node Types):
   - :Report (Properties: name, ipfs_cid)
   - :ThreatActor (Properties: name)
   - :Malware (Properties: name)
   - :Host (Properties: name)
   - :Vulnerability (Properties: name)
   - :Domain (Properties: name)
   - :IpAddress (Properties: name)
   - :MitreTechnique (Properties: id, name, tactic)

2. Allowed Directed Relationships:
   - (:ThreatActor)-[:UTILIZES]->(:Malware)
   - (:Malware)-[:EXPLOITS]->(:Vulnerability)
   - (:Malware)-[:TARGETS]->(:Host)
   - (:ThreatActor)-[:TARGETS]->(:Host)
   - (:Vulnerability)-[:AFFECTS]->(:Host)
   - (:Malware)-[:COMMUNICATES_WITH]->(:Domain)
   - (:Malware)-[:COMMUNICATES_WITH]->(:IpAddress)
   - (AnyNode)-[:FOUND_IN]->(:Report)
   - (AnyNode)-[:MAPS_TO_TTP]->(:MitreTechnique)

=== CRITICAL RULES ===
- Use standard relationship arrows like -[:RELATIONSHIP]-> or <-[:RELATIONSHIP]-.
- Return ONLY the executable Cypher query string.
- Do NOT wrap the code in backticks like ```cypher. Do not write markdown tags.
- Do NOT include any conversation, introductions, explanations, or warnings.
- If you don't know the answer based on the schema, return an empty string.

User Question: 
"""

def convert_english_to_cypher(prompt_string: str) -> str:
    """
    Sends the user query along with the schema rules to the local Ollama instance 
    to extract a raw Cypher command string.
    """
    full_prompt = SYSTEM_PROMPT + f'"{prompt_string}"\nCypher Output:'
    
    payload = {
        "model": MODEL_NAME,
        "prompt": full_prompt,
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=30)
        if response.status_code == 200:
            cypher_query = response.json().get("response", "").strip()
            # Clean up potential accidental markdown wrap-arounds from LLM leakage
            cypher_query = cypher_query.replace("```cypher", "").replace("```", "").strip()
            return cypher_query
        else:
            print(f"⚠️ Local LLM error: Status code {response.status_code}")
            return ""
    except Exception as e:
        print(f"❌ Failed to reach local LLM runtime engine ({e})")
        return ""

def _pack_records(results):
    """Shared record-packing logic: turns Neo4j Record/Node objects into plain dicts."""
    records_output = []
    for record in results:
        record_data = {}
        for key, value in record.items():
            if hasattr(value, "labels"):  # It's a Neo4j Node object
                record_data[key] = dict(value)
                record_data[f"{key}_label"] = list(value.labels)[0]
            else:
                record_data[key] = value
        records_output.append(record_data)
    return records_output


def query_graph_with_driver(driver, english_question: str):
    """
    Same translate-and-execute flow as execute_natural_language_query, but reuses an
    already-open Neo4j driver (e.g. the one a caller like a Streamlit app already holds)
    instead of opening a new connection with this module's own placeholder credentials.

    Returns a dict: {"cypher": <generated query str>, "records": [...], "error": <str or None>}
    """
    cypher_cmd = convert_english_to_cypher(english_question)

    if not cypher_cmd:
        return {"cypher": "", "records": [], "error": "Could not generate a valid Cypher statement."}

    try:
        with driver.session() as session:
            results = session.run(cypher_cmd)
            records_output = _pack_records(results)
        return {"cypher": cypher_cmd, "records": records_output, "error": None}
    except Exception as e:
        return {"cypher": cypher_cmd, "records": [], "error": str(e)}


def execute_natural_language_query(english_question: str):
    """
    Translates the question, fires it into the active Neo4j graph, 
    and handles structured record feedback loops for Developer 2's UI.
    """
    print(f"\n💬 Input Question: '{english_question}'")
    
    # 1. Translate
    cypher_cmd = convert_english_to_cypher(english_question)
    print(f"🤖 Generated Cypher: {cypher_cmd}")
    
    if not cypher_cmd:
        print("Could not generate a valid Cypher statement.")
        return []
        
    # 2. Execute against the database
    records_output = []
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session() as session:
            results = session.run(cypher_cmd)
            records_output = _pack_records(results)
        driver.close()
        print(f"📊 Query complete! Retrieved {len(records_output)} matching tracking entries.")
    except Exception as e:
        print(f"⚠️ Graph execution fault: {e}")
        
    return records_output

if __name__ == "__main__":
    print("====================================================")
    print("🤖 AI Cypher Translation Interface Initialized!")
    print("   Type your cybersecurity question in plain English.")
    print("   Type 'exit' or 'quit' to close the interface.")
    print("====================================================\n")
    
    while True:
        try:
            # Capture user input at runtime
            user_question = input("❓ Ask a question: ").strip()
            
            # Break condition
            if user_question.lower() in ['exit', 'quit', 'q']:
                print("\n👋 Closing natural language query interface.")
                break
                
            if not user_question:
                continue
                
            # Execute the natural language processor pipeline
            results = execute_natural_language_query(user_question)
            
            # Print the formatted output cleanly back to the terminal window
            print("\n📊 Raw Graph Results Data:")
            print(json.dumps(results, indent=2))
            print("-" * 50 + "\n")
            
        except KeyboardInterrupt:
            print("\n👋 Interface interrupted. Exiting.")
            break
