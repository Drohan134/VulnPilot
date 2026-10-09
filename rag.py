# rag.py

from functools import lru_cache
from pathlib import Path

from langchain_chroma import Chroma
from langchain_community.document_loaders import TextLoader
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

BASE_DIR = Path(__file__).resolve().parent
KNOWLEDGE_FILE = BASE_DIR / "knowledge" / "security_basics.txt"
CHROMA_DIR = BASE_DIR / "chroma_db"

EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


@lru_cache(maxsize=1)
def get_embeddings():
    return HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL,
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )


@lru_cache(maxsize=1)
def get_vector_store():
    if not KNOWLEDGE_FILE.exists():
        raise FileNotFoundError(f"Knowledge file not found: {KNOWLEDGE_FILE}")

    loader = TextLoader(str(KNOWLEDGE_FILE), encoding="utf-8")
    documents = loader.load()

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=700,
        chunk_overlap=100,
    )
    chunks = splitter.split_documents(documents)

    return Chroma.from_documents(
        documents=chunks,
        embedding=get_embeddings(),
        persist_directory=str(CHROMA_DIR),
        collection_name="vulnpilot_security_knowledge",
    )


def retrieve_security_context(query: str, k: int = 4) -> str:
    """Retrieve relevant background knowledge for an analysis query."""
    store = get_vector_store()
    documents = store.similarity_search(query, k=k)

    if not documents:
        return "No relevant internal security guidance was retrieved."

    return "\n\n".join(
        f"Source: {doc.metadata.get('source', 'security knowledge')}\n"
        f"{doc.page_content}"
        for doc in documents
    )


if __name__ == "__main__":
    question = "How should a dependency vulnerability be verified?"
    print(retrieve_security_context(question))