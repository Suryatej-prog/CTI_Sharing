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
from ipfs import upload_to_ipfs

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
ABI_PATH = "artifacts/contracts/CTIAnchor.sol/CTIAnchor.json"

NEO4J_URI = "bolt://10.2.2.132:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "ABCDEFGHI"


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

uploaded_file = st.file_uploader(
    "Drop a PDF or text file containing threat intelligence",
    type=["pdf", "txt"]
)

if uploaded_file is not None:

    st.success(f"File Uploaded: {uploaded_file.name}")

    if st.button("Run Full Pipeline"):

        with st.spinner("Running Full Pipeline..."):

            try:

                # Save uploaded file temporarily
                with tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=os.path.splitext(uploaded_file.name)[1]
                ) as tmp:
                    tmp.write(uploaded_file.read())
                    tmp_path = tmp.name

                # ===========================================
                # STEP 0: Upload Report to IPFS
                # ===========================================

                st.info("Uploading report to IPFS...")
                cid = upload_to_ipfs(tmp_path)
                st.success("Report successfully uploaded to IPFS")
                st.code(f"CID: {cid}")
                st.markdown(f"**Gateway URL:** https://gateway.pinata.cloud/ipfs/{cid}")

                # ===========================================
                # STEP 1: AI Extraction + Neo4j
                # ===========================================

                try:
                    st.info("Running AI extraction and writing to Neo4j...")
                    run_bert_graph_pipeline(tmp_path, ipfs_cid=cid)
                    st.success("AI extraction completed. Knowledge Graph written into Neo4j.")
                except Exception as neo4j_err:
                    st.warning("AI extraction ran but Neo4j is currently unreachable. Graph will be available when Dev 1's server is online.")
                    st.info(f"Detail: {str(neo4j_err)}")

                # ===========================================
                # STEP 2: SHA256 Hash
                # ===========================================

                with open(tmp_path, "rb") as f:
                    file_bytes = f.read()

                hash_bytes = hashlib.sha256(file_bytes).digest()
                hash_hex = hash_bytes.hex()

                st.info("SHA-256 Hash")
                st.code(hash_hex)

                # ===========================================
                # STEP 3: Blockchain Anchoring
                # ===========================================

                w3, contract = get_contract()

                if w3.is_connected():

                    account = w3.eth.account.from_key(PRIVATE_KEY)
                    nonce = w3.eth.get_transaction_count(account.address)
                    report_id = uploaded_file.name

                    txn = contract.functions.anchorReport(
                        report_id,
                        hash_bytes,
                        cid
                    ).build_transaction({
                        "from": account.address,
                        "nonce": nonce,
                        "gas": 300000,
                        "gasPrice": w3.eth.gas_price
                    })

                    signed_txn = w3.eth.account.sign_transaction(
                        txn,
                        private_key=PRIVATE_KEY
                    )

                    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
                    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

                    st.success(f"Blockchain Anchor Successful! Block Number: {receipt.blockNumber}")
                    st.code(tx_hash.hex())

                else:
                    st.error("Unable to connect to blockchain.")

                # Delete temp file
                os.unlink(tmp_path)

            except Exception as e:
                st.error(str(e))


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
                RETURN
                a.name AS source,
                type(r) AS relationship,
                b.name AS target
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
                MATCH (a)-[r:ASSOCIATED_WITH]->(b)
                WHERE r.timestamp IS NOT NULL
                RETURN
                    a.name AS source,
                    type(r) AS relationship,
                    b.name AS target,
                    r.timestamp AS timestamp,
                    r.source_report AS report,
                    r.ipfs_cid AS cid,
                    r.confidence AS confidence
                ORDER BY r.timestamp ASC
                LIMIT 50
            """)
            events = result.data()

        if events:
            st.success(f"Timeline loaded: {len(events)} events found")

            for i, event in enumerate(events):
                with st.expander(
                    f"Event {i+1} | {event.get('timestamp', 'N/A')[:19]} | "
                    f"{event.get('source', '?')} -> {event.get('target', '?')}"
                ):
                    st.write(f"**Source Entity:** {event.get('source', 'N/A')}")
                    st.write(f"**Relationship:** {event.get('relationship', 'N/A')}")
                    st.write(f"**Target Entity:** {event.get('target', 'N/A')}")
                    st.write(f"**Timestamp:** {event.get('timestamp', 'N/A')}")
                    st.write(f"**Source Report:** {event.get('report', 'N/A')}")
                    st.write(f"**Confidence:** {event.get('confidence', 'N/A')}")
                    if event.get('cid'):
                        st.markdown(
                            f"**IPFS Source:** https://gateway.pinata.cloud/ipfs/{event.get('cid')}"
                        )
        else:
            st.info("No timeline events found. Run the pipeline first to generate data.")

    except Exception as e:
        st.error(f"Timeline Error: {str(e)}")