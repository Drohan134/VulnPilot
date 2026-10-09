# agent.py

import os
from typing import TypedDict

from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

from scanner import scan_requirements
from rag import retrieve_security_context

load_dotenv()


class VulnPilotState(TypedDict, total=False):
    requirements_text: str
    scan_result: dict
    security_context: str
    report: str
    error: str


def scan_node(state: VulnPilotState) -> dict:
    """Run the deterministic OSV scanner."""
    try:
        result = scan_requirements(state["requirements_text"])
        return {"scan_result": result}
    except Exception as exc:
        return {"error": f"Scanning failed: {exc}"}


def evidence_node(state: VulnPilotState) -> dict:
    """Retrieve general security guidance using local embeddings."""
    result = state.get("scan_result", {})
    findings = result.get("findings", [])

    queries = [
        f"How to assess dependency vulnerabilities and remediate them: "
        f"{finding.get('id', '')} {finding.get('summary', '')}"
        for finding in findings[:5]
    ]

    if not queries:
        queries = ["How to interpret dependency vulnerability scan results."]

    try:
        context = "\n\n".join(
            retrieve_security_context(query) for query in queries
        )
        return {"security_context": context}
    except Exception as exc:
        return {
            "security_context": (
                f"Local security knowledge retrieval failed: {exc}"
            )
        }


def report_node(state: VulnPilotState) -> dict:
    """Generate a report without letting the LLM change scanner results."""
    scan_result = state.get("scan_result", {})
    findings = scan_result.get("findings", [])

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return {
            "report": (
                "LLM report generation skipped: GROQ_API_KEY is not configured.\n\n"
                f"Scanner status: {scan_result.get('status', 'unknown')}\n"
                f"Packages checked: {len(scan_result.get('packages', []))}\n"
                f"Advisory results: {len(findings)}"
            )
        }

    model_name = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

    try:
        llm = ChatGroq(
            model=model_name,
            temperature=0,
            max_retries=2,
        )

        prompt_data = {
            "scanner_status": scan_result.get("status", "unknown"),
            "scanner_message": scan_result.get("message", ""),
            "packages": scan_result.get("packages", []),
            "findings": findings,
            "errors": scan_result.get("errors", []),
            "security_context": state.get("security_context", ""),
        }

        messages = [
            SystemMessage(
                content=(
                    "You are VulnPilot, a careful dependency security analyst. "
                    "Use only the supplied scanner results for claims about "
                    "specific packages and advisories. Do not invent CVEs, "
                    "severity, affected versions, fixes, or references. "
                    "Treat applicability='affected' as a scanner range match, "
                    "not proof that the application is exploitable. "
                    "Explain 'unknown' as unconfirmed, never as safe. "
                    "Explain that a successful scan with no findings means "
                    "no matching advisories were returned by this query, "
                    "not that the dependencies are guaranteed secure. "
                    "Distinguish scanner evidence from general guidance. "
                    "Give a concise summary, findings, limitations, and "
                    "prioritized next steps."
                )
            ),
            HumanMessage(content=str(prompt_data)),
        ]

        response = llm.invoke(messages)
        return {"report": response.content}

    except Exception as exc:
        return {
            "report": (
                "LLM report generation failed. The deterministic scan result "
                "is still available.\n"
                f"Reason: {exc}\n\n"
                f"Scanner status: {scan_result.get('status', 'unknown')}\n"
                f"Packages checked: {len(scan_result.get('packages', []))}\n"
                f"Advisory results: {len(findings)}"
            )
        }


def build_graph():
    workflow = StateGraph(VulnPilotState)

    workflow.add_node("scan", scan_node)
    workflow.add_node("retrieve_evidence", evidence_node)
    workflow.add_node("generate_report", report_node)

    workflow.add_edge(START, "scan")
    workflow.add_edge("scan", "retrieve_evidence")
    workflow.add_edge("retrieve_evidence", "generate_report")
    workflow.add_edge("generate_report", END)

    return workflow.compile()


app = build_graph()


def run_vulnpilot(requirements_text: str) -> dict:
    """Public entry point used by the Streamlit application."""
    return app.invoke({"requirements_text": requirements_text})


if __name__ == "__main__":
    sample = """
django==1.2
requests==2.31.0
flask==2.0.0
"""
    result = run_vulnpilot(sample)

    print("\n=== VULNPILOT REPORT ===\n")
    print(result.get("report", "No report generated."))

    print("\n=== RAW SCANNER RESULTS ===\n")
    print(result.get("scan_result", {}))