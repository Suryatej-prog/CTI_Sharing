import streamlit as st
import json
import hashlib
import sys
import os
import tempfile
from web3 import Web3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline import run_pipeline
from neo4j import GraphDatabase
from ipfs import upload_to_ipfs
from nl_query_engine import query_graph_with_driver

st.set_page_config(page_title="CTI Knowledge Graph Pipeline", layout="wide")

st.title("CTI Threat Intelligence Pipeline")
st.markdown("AI Extraction -> Blockchain Anchoring -> Knowledge Graph Visualization")
st.warning(
    "This is an academic prototype (MVP) for cybersecurity research. "
    "Do not upload sensitive, classified, or real production threat intelligence data."
)

st.divider()

RPC_URL = "http://127.0.0.1:8545"
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ABI_PATH = "C:\\Users\\tanish\\CTI_Sharing\\artifacts\\contracts\\CTIAnchor.sol\\CTIAnchor.json"

NEO4J_URI = "neo4j://127.0.0.1:7687"
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


# -------------------------------
# Upload Section
# -------------------------------

st.header("1. Upload CTI Report")

uploaded_files = st.file_uploader(
    "Drop one or more PDF/text files containing threat intelligence",
    type=["pdf", "txt"],
    accept_multiple_files=True
)

if uploaded_files:

    st.success(f"{len(uploaded_files)} file(s) uploaded successfully")
    for uf in uploaded_files:
        st.write(f"- {uf.name}")

    if st.button("Run Full Pipeline (Multi-Source Fusion)"):

        with st.spinner("Running Multi-Source CTI Fusion Pipeline..."):

            fusion_results = []

            for uploaded_file in uploaded_files:

                st.markdown(f"---\n### Processing: {uploaded_file.name}")

                try:

                    with tempfile.NamedTemporaryFile(
                        delete=False,
                        suffix=os.path.splitext(uploaded_file.name)[1]
                    ) as tmp:
                        tmp.write(uploaded_file.read())
                        tmp_path = tmp.name

                    # STEP 0: IPFS Upload
                    st.info(f"Uploading {uploaded_file.name} to IPFS...")
                    cid = upload_to_ipfs(tmp_path)
                    st.success("Uploaded to IPFS")
                    st.code(f"CID: {cid}")
                    st.markdown(f"**Gateway URL:** https://gateway.pinata.cloud/ipfs/{cid}")

                    # STEP 1: AI Extraction + Neo4j
                    try:
                        st.info("Running BERT extraction and fusing into Knowledge Graph...")
                        run_pipeline(
                            file_path=tmp_path,
                            ipfs_cid=cid,
                            enable_mitre=False
                        )
                        st.success("Fused into Knowledge Graph successfully.")
                    except Exception as neo4j_err:
                        st.warning("Neo4j unreachable. Graph will sync when Dev 1's server is online.")
                        st.info(f"Detail: {str(neo4j_err)}")

                    # STEP 2: SHA256
                    with open(tmp_path, "rb") as f:
                        file_bytes = f.read()
                    hash_bytes = hashlib.sha256(file_bytes).digest()
                    hash_hex = hash_bytes.hex()
                    st.info("SHA-256 Hash")
                    st.code(hash_hex)

                    # STEP 3: Blockchain Anchoring
                    w3, contract = get_contract()

                    if w3.is_connected():

                        account = w3.eth.account.from_key(PRIVATE_KEY)
                        nonce = w3.eth.get_transaction_count(account.address)

                        txn = contract.functions.anchorReport(
                            uploaded_file.name,
                            hash_bytes,
                            cid
                        ).build_transaction({
                            "from": account.address,
                            "nonce": nonce,
                            "gas": 300000,
                            "gasPrice": w3.eth.gas_price
                        })

                        signed_txn = w3.eth.account.sign_transaction(
                            txn, private_key=PRIVATE_KEY
                        )
                        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
                        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

                        st.success(f"Blockchain Anchor Successful! Block #{receipt.blockNumber}")
                        st.code(tx_hash.hex())

                        fusion_results.append({
                            "file": uploaded_file.name,
                            "cid": cid,
                            "hash": hash_hex,
                            "block": receipt.blockNumber,
                            "tx": tx_hash.hex()
                        })

                    else:
                        st.error("Unable to connect to blockchain.")

                    os.unlink(tmp_path)

                except Exception as e:
                    st.error(f"Error processing {uploaded_file.name}: {str(e)}")

            if fusion_results:
                st.divider()
                st.success(f"Multi-Source Fusion Complete! {len(fusion_results)} reports fused into Knowledge Graph.")
                st.subheader("Fusion Summary")
                for r in fusion_results:
                    with st.expander(f"Report: {r['file']}"):
                        st.write(f"**IPFS CID:** {r['cid']}")
                        st.write(f"**SHA-256:** {r['hash']}")
                        st.write(f"**Block Number:** {r['block']}")
                        st.write(f"**Transaction:** {r['tx']}")
                        st.markdown(f"**IPFS URL:** https://gateway.pinata.cloud/ipfs/{r['cid']}")


st.divider()

# -------------------------------
# Neo4j Graph Viewer
# -------------------------------

st.header("2. Knowledge Graph")

if st.button("Load Graph from Neo4j"):

    try:
        driver = get_neo4j()
        with driver.session() as session:
            result = session.run("""
                MATCH (a)-[r]->(b)
                WHERE type(r) <> 'FOUND_IN'
                  AND type(r) <> 'MAPS_TO_TTP'
                RETURN a.name AS source,
                       type(r) AS relationship,
                       b.name AS target,
                       r.source_report AS report
                LIMIT 50
            """)
            records = result.data()

        if records:
            st.success(f"Graph Loaded Successfully ({len(records)} Relationships)")
            for r in records:
                st.write(
                    f"**{r['source']}** "
                    f"--[{r['relationship']}]--> "
                    f"**{r['target']}**"
                    + (f" *(from {r['report']})*" if r.get('report') else "")
                )
        else:
            st.info("Knowledge Graph is empty.")

    except Exception as e:
        st.error(f"Neo4j Error: {str(e)}")

st.divider()

# -------------------------------
# Threat Timeline
# -------------------------------

st.header("3. Threat Timeline")

if st.button("Generate Threat Timeline"):

    try:
        driver = get_neo4j()

        with driver.session() as session:
            result = session.run("""
                MATCH (a)-[r]->(b)
                WHERE type(r) <> 'FOUND_IN'
                  AND type(r) <> 'MAPS_TO_TTP'
                RETURN
                    a.name AS source,
                    type(r) AS relationship,
                    b.name AS target,
                    r.source_report AS report,
                    r.ipfs_cid AS cid
                LIMIT 50
            """)
            events = result.data()

        if events:
            st.success(f"Timeline loaded: {len(events)} events found")

            for i, event in enumerate(events):
                with st.expander(
                    f"Event {i+1}: {event['source']} -> {event['target']}"
                ):
                    st.write(f"**Source:** {event['source']}")
                    st.write(f"**Relationship:** {event['relationship']}")
                    st.write(f"**Target:** {event['target']}")
                    st.write(f"**Report:** {event.get('report','N/A')}")
                    if event.get("cid"):
                        st.write(f"**IPFS CID:** {event['cid']}")

        else:
            st.info("No timeline events found.")

    except Exception as e:
        st.error(f"Timeline Error: {e}")

st.divider()

# -------------------------------
# Natural Language Query (nl_query_engine.py)
# -------------------------------

st.header("4. Ask the Graph a Question")
st.caption(
    "Type a question in plain English. It's translated to Cypher by a local "
    "Ollama LLM and run against the same Neo4j graph used above."
)

nl_question = st.text_input(
    "Your question",
    placeholder="e.g. Which malware targets hosts affected by CVE-2023-1234?"
)

if st.button("Run Natural Language Query"):
    if not nl_question.strip():
        st.warning("Please enter a question first.")
    else:
        with st.spinner("Translating question to Cypher and querying the graph..."):
            try:
                driver = get_neo4j()
                result = query_graph_with_driver(driver, nl_question)
            except Exception as e:
                result = {"cypher": "", "records": [], "error": str(e)}

        if result["cypher"]:
            st.markdown("**Generated Cypher:**")
            st.code(result["cypher"], language="cypher")

        if result["error"]:
            st.error(f"Query Error: {result['error']}")
        elif result["records"]:
            st.success(f"Query returned {len(result['records'])} result(s).")
            st.dataframe(result["records"])
        else:
            st.info("Query ran successfully but returned no results.")
