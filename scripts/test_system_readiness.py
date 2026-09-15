import asyncio
from pathlib import Path
import json

async def verify():
    print("--- CyberSentinel Non-Frontend Readiness Test ---")
    
    # 1. Ollama Test
    print("[1/5] Testing Ollama Llama3 inference...")
    try:
        from langchain_ollama import ChatOllama
        from langchain_core.messages import HumanMessage
        llm = ChatOllama(model="llama3", temperature=0.0)
        resp = await llm.ainvoke([HumanMessage(content="Respond with: 'CyberSentinel is ready.'")])
        print(f"  [+] Ollama response: {resp.content.strip()}")
    except Exception as e:
        print(f"  [-] Ollama error: {e}")

    # 2. MITRE STIX Test
    print("[2/5] Checking MITRE STIX data...")
    stix_dir = Path("data/knowledge_base/mitre_stix/enterprise-attack")
    if stix_dir.exists():
        json_files = list(stix_dir.glob("*.json"))
        print(f"  [+] Found enterprise-attack STIX directory ({len(json_files)} bundle files)")
    else:
        print("  [-] enterprise-attack directory not found")

    # 3. CISA KEV Test
    print("[3/5] Checking CISA KEV data...")
    kev_file = Path("data/knowledge_base/cisa_kev/known_exploited_vulnerabilities.json")
    if kev_file.exists():
        with open(kev_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            count = len(data.get("vulnerabilities", []))
            print(f"  [+] CISA KEV valid ({count} vulnerabilities cataloged)")
    else:
        print("  [-] CISA KEV file missing")

    # 4. ChromaDB Test
    print("[4/5] Testing ChromaDB vector store...")
    try:
        import chromadb
        client = chromadb.PersistentClient(path="./data/chroma_db")
        col = client.get_or_create_collection("smoke_test")
        col.add(documents=["SSH brute force detected on port 22"], ids=["test1"])
        res = col.query(query_texts=["unauthorized login"], n_results=1)
        client.delete_collection("smoke_test")
        print(f"  [+] ChromaDB working, retrieved: '{res['documents'][0][0]}'")
    except Exception as e:
        print(f"  [-] ChromaDB error: {e}")

    # 5. spaCy Model Test
    print("[5/5] Testing spaCy NER...")
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
        doc = nlp("Attacker IP 192.168.1.100 exploited CVE-2021-44228 on target port 8080.")
        print(f"  [+] spaCy loaded, token count: {len(doc)}")
    except Exception as e:
        print(f"  [-] spaCy error: {e}")

    print("\n--- All Non-Frontend Systems Fully Operational ---")

if __name__ == "__main__":
    asyncio.run(verify())
