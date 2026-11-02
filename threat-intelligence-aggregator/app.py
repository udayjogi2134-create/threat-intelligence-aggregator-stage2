import database
import feed_manager
import normalizer
import pandas as pd
import reporting
import requests
import streamlit as st
from risk_engine import severity

st.set_page_config(
    page_title="Threat Intelligence Aggregator",
    page_icon="🛡️",
    layout="wide",
)
database.init_db()

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(145deg, #0b1425 0%, #101d32 55%, #0b1425 100%);
        color: #e7eefb;
    }
    .block-container {
        max-width: 1180px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }
    h1, h2, h3 { color: #e8efff; }
    [data-testid="stMetric"] {
        background: #111e32;
        border: 1px solid #223450;
        border-radius: 14px;
        padding: 18px 20px;
    }
    [data-testid="stMetricLabel"] { color: #8fa9ce; }
    [data-testid="stMetricValue"] { color: #f0f5ff; }
    [data-testid="stVerticalBlockBorderWrapper"] {
        background: rgba(17, 30, 50, 0.88);
        border-color: #223450;
        border-radius: 14px;
    }
    [data-testid="stDataFrame"] {
        border: 1px solid #223450;
        border-radius: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Threat Intelligence Aggregator")
st.caption("Live indicator triage, correlation, and feed imports.")
def normalize_manual_indicator(selected_type, raw_value):
    candidates = (
        ("URL", "IP", "DOMAIN")
        if selected_type == "AUTO"
        else (selected_type,)
    )
    errors = []
    for kind in candidates:
        try:
            return kind, normalizer.normalize_ioc(kind, raw_value)
        except ValueError as exc:
            errors.append(str(exc))
    raise ValueError(errors[-1] if errors else "Enter a valid IP, domain, or URL.")


entry_column, feed_column = st.columns([1.2, 0.8], gap="medium")

with entry_column, st.container(border=True):
    st.subheader("Add an indicator")
    with st.form("manual_ioc_form", clear_on_submit=True):
        type_column, value_column = st.columns([1, 2.8])
        with type_column:
            manual_type = st.selectbox(
                "Type",
                ["AUTO", "IP", "DOMAIN", "URL"],
                format_func=lambda value: {
                    "AUTO": "Auto-detect",
                    "IP": "IP address",
                    "DOMAIN": "Domain",
                    "URL": "URL",
                }[value],
            )
        with value_column:
            manual_value = st.text_input(
                "Indicator value",
                placeholder="192.0.2.10, example.org, or https://example.org",
            )
        indicator_submitted = st.form_submit_button(
            "Add indicator",
            type="primary",
        )

    if indicator_submitted:
        try:
            kind, canonical_value = normalize_manual_indicator(
                manual_type,
                manual_value,
            )
            database.upsert_indicators([
                (kind, canonical_value, "manual input"),
            ])
            st.success(f"Added {kind.lower()}: {canonical_value}")
        except ValueError as exc:
            st.error(str(exc))

with feed_column:
    with st.container(border=True):
        st.subheader("Import a feed")
        st.caption("CSV, TXT, or JSON")
        uploads = st.file_uploader(
            "Choose feed files",
            type=["csv", "txt", "json"],
            accept_multiple_files=True,
            label_visibility="collapsed",
        )
        if st.button("Import feed", type="primary", key="import_files"):
            if not uploads:
                st.warning("Choose at least one file first.")
            else:
                for uploaded in uploads:
                    try:
                        accepted, rejected = feed_manager.process_local_upload(
                            uploaded.name,
                            uploaded.getvalue(),
                        )
                        st.success(
                            f"{uploaded.name}: {accepted} indicators imported; "
                            f"{rejected} rejected."
                        )
                    except (ValueError, OSError) as exc:
                        st.error(f"{uploaded.name}: {exc}")

        with st.expander("Import from an HTTPS feed URL"):
            with st.form("https_feed_form"):
                feed_url = st.text_input(
                    "HTTPS feed URL",
                    placeholder="https://example.org/feed.csv",
                )
                fetch_feed = st.form_submit_button("Fetch feed")
            if fetch_feed:
                if not feed_url.strip():
                    st.warning("Enter an HTTPS feed URL.")
                else:
                    try:
                        accepted, rejected = feed_manager.fetch_https_feed(
                            feed_url.strip()
                        )
                        st.success(
                            f"{accepted} indicators imported; {rejected} rejected."
                        )
                    except (ValueError, OSError, requests.RequestException) as exc:
                        st.error(f"Feed import failed: {exc}")

st.divider()

rows = database.list_indicators()
df = pd.DataFrame(rows)
feed_runs = pd.DataFrame(database.list_feed_runs(limit=1000))
if feed_runs.empty:
    feed_sources = set()
else:
    feed_sources = set(
        feed_runs.loc[feed_runs["status"] == "success", "source"].dropna()
    )

if df.empty:
    high_critical = 0
    sightings = 0
    table = pd.DataFrame(
        columns=["Priority", "Score", "Type", "Indicator", "Feeds", "Sightings"]
    )
else:
    df["severity"] = df["risk_score"].map(severity)
    high_critical = int(df["severity"].isin(["High", "Critical"]).sum())
    sightings = int(df["source_count"].sum())
    df["priority"] = df["severity"].str.upper()
    df["display_type"] = df["type"].str.lower()
    df["feeds"] = df["sources"].fillna("").map(
        lambda value: sum(
            source.strip() in feed_sources
            for source in str(value).split("|")
            if source.strip()
        )
    )
    table = df.rename(
        columns={
            "risk_score": "Score",
            "value": "Indicator",
            "source_count": "Sightings",
            "priority": "Priority",
            "display_type": "Type",
            "feeds": "Feeds",
        }
    )[["Priority", "Score", "Type", "Indicator", "Feeds", "Sightings"]]

metric_columns = st.columns(4)
metric_columns[0].metric("Indicators", len(df))
metric_columns[1].metric("Feeds", len(feed_sources))
metric_columns[2].metric("High / critical", high_critical)
metric_columns[3].metric("Sightings", sightings)

with st.container(border=True):
    st.subheader("Indicators")
    filter_column, risk_column, search_column = st.columns([1, 1, 2])
    available_types = sorted(df["type"].dropna().unique()) if not df.empty else []
    with filter_column:
        selected_types = st.multiselect(
            "Type",
            available_types,
            default=available_types,
            format_func=lambda value: value.lower(),
        )
    with risk_column:
        minimum_risk = st.slider("Minimum score", 0, 100, 0)
    with search_column:
        query = st.text_input("Search indicators or sources")

    filtered_df = df.copy()
    if not df.empty:
        filtered_df = df[
            df["type"].isin(selected_types)
            & (df["risk_score"] >= minimum_risk)
        ].copy()
        if query:
            mask = filtered_df.apply(
                lambda row: query.casefold()
                in " ".join(map(str, row.values)).casefold(),
                axis=1,
            )
            filtered_df = filtered_df[mask]

        filtered_df["Priority"] = filtered_df["severity"].str.upper()
        filtered_df["Score"] = filtered_df["risk_score"]
        filtered_df["Type"] = filtered_df["type"].str.lower()
        filtered_df["Indicator"] = filtered_df["value"]
        filtered_df["Feeds"] = filtered_df["sources"].fillna("").map(
            lambda value: sum(
                source.strip() in feed_sources
                for source in str(value).split("|")
                if source.strip()
            )
        )
        filtered_df["Sightings"] = filtered_df["source_count"]
        shown = filtered_df[
            ["Priority", "Score", "Type", "Indicator", "Feeds", "Sightings"]
        ]
    else:
        shown = table

    st.dataframe(shown, width="stretch", hide_index=True)

    if not df.empty:
        export_rows = filtered_df.to_dict(orient="records")
        export_column, json_column, text_column = st.columns(3)
        export_column.download_button(
            "Download CSV",
            reporting.to_csv(export_rows),
            "threat-report.csv",
            "text/csv",
            width="stretch",
        )
        json_column.download_button(
            "Download JSON",
            reporting.to_json(export_rows),
            "threat-report.json",
            "application/json",
            width="stretch",
        )
        text_column.download_button(
            "Download TXT list",
            reporting.to_txt(export_rows),
            "ioc-list.txt",
            "text/plain",
            width="stretch",
        )

st.divider()
history_column, rejected_column = st.columns(2)
with history_column:
    with st.container(border=True):
        st.subheader("Feed history")
        st.dataframe(
            feed_runs,
            width="stretch",
            hide_index=True,
        )
with rejected_column:
    with st.container(border=True):
        st.subheader("Rejected records")
        st.dataframe(
            pd.DataFrame(database.list_rejections()),
            width="stretch",
            hide_index=True,
        )

st.caption("Risk scores are heuristic triage hints, not proof of maliciousness.")
