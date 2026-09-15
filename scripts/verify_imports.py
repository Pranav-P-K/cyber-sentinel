import sys
print(f"Python: {sys.version}")

try:
    import fastapi
    print(f"fastapi: {fastapi.__version__}")
except Exception as e:
    print(f"fastapi error: {e}")

try:
    import uvicorn
    print(f"uvicorn: {uvicorn.__version__}")
except Exception as e:
    print(f"uvicorn error: {e}")

try:
    import pydantic
    print(f"pydantic: {pydantic.__version__}")
except Exception as e:
    print(f"pydantic error: {e}")

try:
    import sqlalchemy
    print(f"sqlalchemy: {sqlalchemy.__version__}")
except Exception as e:
    print(f"sqlalchemy error: {e}")

try:
    import chromadb
    print(f"chromadb: {chromadb.__version__}")
except Exception as e:
    print(f"chromadb error: {e}")

try:
    import torch
    print(f"torch: {torch.__version__}")
except Exception as e:
    print(f"torch error: {e}")

try:
    import transformers
    print(f"transformers: {transformers.__version__}")
except Exception as e:
    print(f"transformers error: {e}")

try:
    import sentence_transformers
    print(f"sentence_transformers: {sentence_transformers.__version__}")
except Exception as e:
    print(f"sentence_transformers error: {e}")

try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
    print(f"spacy: {spacy.__version__} (en_core_web_sm loaded)")
except Exception as e:
    print(f"spacy error: {e}")

try:
    import langchain
    print(f"langchain: {langchain.__version__}")
except Exception as e:
    print(f"langchain error: {e}")

try:
    import ragas
    print(f"ragas: {ragas.__version__}")
except Exception as e:
    print(f"ragas error: {e}")

try:
    import stix2
    print(f"stix2: {stix2.__version__}")
except Exception as e:
    print(f"stix2 error: {e}")

print("--- Verification Finished ---")
