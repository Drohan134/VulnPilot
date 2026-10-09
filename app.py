# app.py

import pandas as pd
import streamlit as st

from agent import run_vulnpilot

st.set_page_config(
    page_title="VulnPilot",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ VulnPilot")
st.subheader("Agentic AI Dependency Security Analyst")

st.write(
    "Upload a pinned Python requirements file to check dependency advisories "
    "using OSV, retrieve local security guidance, and generate an AI report."
)

uploaded_file = st.file_uploader(
    "Upload requirements.txt",
    type=["txt"],
)

default_text = """django==1.2
requests==2.31.0
flask==2.0.0
"""

with st.expander("Or paste requirements manually", expanded=uploaded_file is None):
    requirements_text = st.text_area(
        "Requirements",
        value=default_text,
        height=140,
        help="For reliable version checks, use pinned versions such as requests==2.31.0.",
    )

if st.button("Scan dependencies", type="primary", use_container_width=True):
    if uploaded_file is not None:
        try:
            text = uploaded_file.getvalue().decode("utf-8-sig")
        except UnicodeDecodeError:
            st.error("The uploaded file must be UTF-8 encoded.")
            st.stop()
    else:
        text = requirements_text

    if not text.strip():
        st.warning("Upload a file or paste your requirements first.")
        st.stop()

    with st.spinner("Scanning dependencies and generating the report..."):
        try:
            result = run_vulnpilot(text)
            st.session_state["vulnpilot_result"] = result
        except Exception as exc:
            st.error(f"VulnPilot workflow failed: {exc}")
            st.stop()

result = st.session_state.get("vulnpilot_result")

if result:
    scan_result = result.get("scan_result", {})
    packages = scan_result.get("packages", [])
    findings = scan_result.get("findings", [])
    errors = scan_result.get("errors", [])

    st.divider()
    st.header("Scan summary")

    col1, col2, col3 = st.columns(3)
    col1.metric("Packages parsed", len(packages))
    col2.metric("Advisory results", len(findings))
    col3.metric("Packages with scan errors", len(errors))

    st.caption(
        f"Status: {scan_result.get('status', 'unknown')} — "
        f"{scan_result.get('message', '')}"
    )

    if findings:
        st.header("Vulnerability findings")

        display_rows = []
        for finding in findings:
            display_rows.append({
                "Package": finding.get("package", ""),
                "Version": finding.get("version", ""),
                "Advisory ID": finding.get("id", ""),
                "Applicability": finding.get("applicability", "unknown"),
                "Severity": finding.get("severity", "Unknown"),
                "Summary": finding.get("summary", ""),
                "References": ", ".join(finding.get("references", [])),
            })

        st.dataframe(
            pd.DataFrame(display_rows),
            use_container_width=True,
            hide_index=True,
        )

        for finding in findings:
            title = (
                f"{finding.get('id', 'Advisory')} — "
                f"{finding.get('package', '')} "
                f"{finding.get('version', '')}"
            )

            with st.expander(title):
                st.write("**Applicability:**", finding.get("applicability", "unknown"))
                st.write("**Summary:**", finding.get("summary", ""))
                st.write("**Details:**", finding.get("details") or "No additional details.")
                st.write("**Aliases:**", ", ".join(finding.get("aliases", [])) or "None provided.")

                references = finding.get("references", [])
                if references:
                    st.write("**References:**")
                    for url in references:
                        st.markdown(f"- [{url}]({url})")

        csv_data = pd.DataFrame(display_rows).to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download findings as CSV",
            data=csv_data,
            file_name="vulnpilot_findings.csv",
            mime="text/csv",
        )
    else:
        st.info(
            "No advisory results were returned for the packages checked. "
            "This does not guarantee that the dependencies are secure."
        )

    if errors:
        st.warning("Some packages could not be checked.")
        st.dataframe(pd.DataFrame(errors), use_container_width=True, hide_index=True)

    st.header("AI security report")
    st.markdown(result.get("report", "No report was generated."))

    with st.expander("Package scan details"):
        if packages:
            st.dataframe(pd.DataFrame(packages), use_container_width=True, hide_index=True)
        else:
            st.write("No supported requirements were parsed.")