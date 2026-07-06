import streamlit as st
import json
import hashlib
import sys
import os
import tempfile
from web3 import Web3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline import run_bert_graph_pipeline
from neo4j import GraphDatabase

st.set_page_config(page_title="CTI Knowledge Graph Pipeline", layout="wide")

st.title("CTI Threat Intelligence Pipeline")
st.markdown("AI Extraction -> Blockchain Anchoring -> Knowledge Graph Visualization")
st.warning("This is an academic prototype (MVP) for cybersecurity research. Do not upload sensitive, classified, or real production threat intelligence data.")

st.divider()

RPC_URL = "http://127.0.0.1:8545"
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ABI_PATH = "artifacts/contracts/CTIAnchor.sol/CTIAnchor.json"
NEO4J_URI = "bolt://10.2.2.132:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "12345678"

@st.cache_resource
def get_contract():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    with open(ABI_PATH) as f:
        contract_json = json.load(f)
    abi = contract_json["abi"]
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)
    return w3, contract

@st.cache_resource
def get_neo4j():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# --- File Upload Section ---
st.header("1. Upload CTI Report")
uploaded_file = st.file_uploader("Drop a PDF or text file containing threat intelligence", type=["pdf", "txt"])

if uploaded_file is not None:
    st.success("File uploaded: " + uploaded_file.name)

    if st.button("Run Full Pipeline"):
        with st.spinner("Running AI extraction and graph ingestion..."):
            try:
                # Save uploaded file temporarily
                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp:
                    tmp.write(uploaded_file.read())
                    tmp_path = tmp.name

                # Step 1: Run Gemini + Neo4j pipeline
                run_bert_graph_pipeline(tmp_path)
                st.success("AI extraction complete! Triples written to Neo4j graph.")

                # Step 2: Hash the file content and anchor to blockchain
                with open(tmp_path, "rb") as f:
                    file_bytes = f.read()
                hash_bytes = hashlib.sha256(file_bytes).digest()
                hash_hex = hash_bytes.hex()

                st.info("SHA-256 Hash: " + hash_hex)

                w3, contract = get_contract()
                if w3.is_connected():
                    account = w3.eth.account.from_key(PRIVATE_KEY)
                    nonce = w3.eth.get_transaction_count(account.address)
                    report_id = uploaded_file.name

                    txn = contract.functions.anchorHash(report_id, hash_bytes).build_transaction({
                        "from": account.address,
                        "nonce": nonce,
                        "gas": 200000,
                        "gasPrice": w3.eth.gas_price
                    })
                    signed_txn = w3.eth.account.sign_transaction(txn, private_key=PRIVATE_KEY)
                    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
                    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                    st.success("Anchored to blockchain! Block #" + str(receipt.blockNumber))
                    st.code("Transaction Hash: " + tx_hash.hex())

                os.unlink(tmp_path)

            except Exception as e:
                st.error("Error: " + str(e))

st.divider()

# --- Graph Visualization Section ---
st.header("2. Knowledge Graph")

if st.button("Load Graph from Neo4j"):
    try:
        driver = get_neo4j()
        with driver.session() as session:
            result = session.run("""
                MATCH (a)-[r]->(b)
                RETURN a.name as source, type(r) as relationship, b.name as target
                LIMIT 50
            """)
            records = result.data()

        if records:
            st.success("Graph loaded! " + str(len(records)) + " relationships found.")
            for r in records:
                st.write(f"**{r['source']}** --[{r['relationship']}]--> **{r['target']}**")
        else:
            st.info("No graph data found. Run the pipeline first.")

    except Exception as e:
        st.error("Neo4j Error: " + str(e))