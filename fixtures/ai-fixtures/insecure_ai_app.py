"""Insecure AI application fixture with seeded OWASP LLM Top 10 vulnerabilities."""
import os
import openai
from langchain.agents import tool
from langchain.prompts import PromptTemplate

# LLM02: Sensitive Info / Exposed API Key in code
OPENAI_API_KEY = "sk-proj-fakekeyseededforllmtestingonlynotarealkey12345678"

def insecure_chat_completion(user_input: str):
    # LLM01: Direct prompt injection via string formatting
    raw_prompt = f"You are a helpful banking assistant. Answer this query: {user_input}"
    client = openai.OpenAI(api_key=OPENAI_API_KEY)
    
    # LLM10: Unbounded consumption - missing max_tokens and rate limit
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": raw_prompt}]
    )
    
    # LLM05: Insecure output handling - model output passed to eval
    model_output = response.choices[0].message.content
    if "calc:" in model_output:
        code_to_eval = model_output.replace("calc:", "")
        result = eval(code_to_eval)  # Dangerous eval of LLM output
        return result
    return model_output


@tool
def delete_database_record(record_id: str):
    """LLM06: Excessive agency - destructive database tool without human-in-the-loop approval."""
    # Performs destructive operation directly
    return f"Deleted record {record_id} without confirmation"


def retrieve_user_documents(query_text: str):
    """LLM08: Vector search without tenant isolation filter."""
    import chromadb
    client = chromadb.Client()
    collection = client.get_or_create_collection("customer_docs")
    # Query without where={"tenant_id": current_user} filter
    results = collection.query(query_texts=[query_text], n_results=5)
    return results
