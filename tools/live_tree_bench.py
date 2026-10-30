"""Stage 6: Live & Simulated Investigation Tree Calibration Benchmark (`tools/live_tree_bench.py`).

Usage:
  python -m tools.live_tree_bench --query "matanshi" --simulate
  python -m tools.live_tree_bench --query "matanshi" --live
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from osnit.store import Store
from osnit.web_osint import (
    ReconJobManager,
    SearchTargetProfile,
    UnifiedReconEngine,
)


def _build_simulated_environment(query: str):
    """Deterministic multi-branch OSINT simulation for calibrating tree depth, Top-3 disambiguation,
    social tag context mining, and automated Dork document ingestion."""
    q_clean = query.strip().lstrip("@") or "matanshi"

    def search_fn(dork_q: str) -> list[dict[str, str]]:
        return [
            {
                "title": f"{q_clean} (@{q_clean}) • Instagram photos and videos",
                "url": f"https://www.instagram.com/{q_clean}/",
                "snippet": f"Tel Aviv | Cyber researcher | Brother of @avi_{q_clean} | Contact: {q_clean}@cyber-il.org",
            },
            {
                "title": f"{q_clean} Official Resume & Team Roster PDF",
                "url": f"https://files.cyber-il.org/docs/{q_clean}_roster.csv",
                "snippet": f"Full roster and contact details for {q_clean} and team.",
            },
            {
                "title": f"{q_clean}_music (@{q_clean}_music) • Instagram",
                "url": f"https://www.instagram.com/{q_clean}_music/",
                "snippet": f"DJ & Producer in Haifa | Booking: booking@{q_clean}.co.il",
            },
        ]

    def http_fetcher(url: str, timeout: float = 10.0, headers: dict | None = None) -> tuple[int, str]:
        u_low = url.lower()
        if u_low.endswith(".csv"):
            csv_body = (
                "full_name,phone,email,id_number,organization\n"
                f"מתן שי,054-7654321,{q_clean}@cyber-il.org,012345678,CyberIL Labs\n"
                f"אבי שי,052-1112233,avi@{q_clean}.co.il,,CyberIL Labs\n"
            )
            return 200, csv_body
        if "instagram.com" in u_low and "_music" not in u_low:
            html = f"""
            <html>
              <head>
                <meta property="og:title" content="Matan Shi (@{q_clean}) • Instagram" />
                <meta property="og:description" content="Tel Aviv | Founder @cyber_il_labs | Brother @avi_{q_clean} | Photo by @studio_dan | {q_clean}@cyber-il.org | 054-7654321" />
                <meta property="og:image" content="https://cdn.example.com/{q_clean}_avatar.jpg" />
              </head>
              <body>
                <p>Family dinner with my brother @avi_{q_clean} in Tel Aviv! Co-founder at @cyber_il_labs. Photo credit: @studio_dan</p>
                <a href="https://files.cyber-il.org/docs/{q_clean}_roster.csv">Team Roster CSV</a>
              </body>
            </html>
            """
            return 200, html
        if "github.com" in u_low:
            return 200, json.dumps({
                "login": q_clean,
                "name": "Matan Shi",
                "bio": f"Security Engineer in Tel Aviv | @{q_clean}",
                "location": "Tel Aviv, Israel",
                "email": f"{q_clean}@cyber-il.org",
                "blog": f"https://cyber-il.org/~{q_clean}",
                "company": "CyberIL Labs",
                "avatar_url": f"https://avatars.example.com/{q_clean}.png",
            })
        return 200, f"<html><head><title>{q_clean}</title></head><body>Profile of @{q_clean}</body></html>"

    def bytes_fetcher(url: str) -> tuple[int, bytes]:
        if url.lower().endswith(".csv"):
            csv_body = (
                "full_name,phone,email,id_number,organization\n"
                f"מתן שי,054-7654321,{q_clean}@cyber-il.org,012345678,CyberIL Labs\n"
                f"אבי שי,052-1112233,avi@{q_clean}.co.il,,CyberIL Labs\n"
            )
            return 200, csv_body.encode("utf-8")
        return 404, b""

    return search_fn, http_fetcher, bytes_fetcher


def format_ascii_tree(tree_data: dict[str, Any]) -> str:
    """Format an Investigation Tree snapshot into a readable ASCII tree diagram."""
    lines: list[str] = []
    counts = tree_data.get("counts") or tree_data.get("stats") or {}
    lines.append("=" * 78)
    lines.append(
        f"🌳 INVESTIGATION TREE REPORT | job_id={tree_data.get('job_id')} | "
        f"nodes={counts.get('total_nodes', len(tree_data.get('nodes') or []))} | "
        f"edges={counts.get('total_edges', len(tree_data.get('edges') or []))} | "
        f"max_depth={counts.get('max_depth', 0)}"
    )
    lines.append("=" * 78)

    top3 = tree_data.get("top3_candidates") or tree_data.get("top_candidates") or []
    if top3:
        lines.append(f"⚖️  Top-{len(top3)} Candidates for Disambiguation:")
        for c in top3:
            lines.append(
                f"   [#{c.get('candidate_rank') or 1}] {c.get('label')} ({c.get('platform')}) "
                f"— conf={int((c.get('confidence') or 0) * 100)}% | status={c.get('status')} | {c.get('discovery_reason')}"
            )
        lines.append("-" * 78)

    def _walk(node: dict[str, Any], prefix: str = "", is_last: bool = True):
        connector = "└── " if is_last else "├── "
        conf_pct = int(round(float(node.get("confidence") or 0.0) * 100))
        meta = node.get("metadata") or {}
        rel_tag = meta.get("relation_label_he") or meta.get("relation_label") or ""
        rel_str = f" [{rel_tag}]" if rel_tag else ""
        doc_str = f" [ingested_source_id=#{node.get('ingested_source_id')}]" if node.get("ingested_source_id") else ""
        lines.append(
            f"{prefix}{connector}({node.get('node_type')}) {node.get('label')} "
            f"[{node.get('status')} | {conf_pct}%]{rel_str}{doc_str}"
        )
        if node.get("discovery_reason"):
            sub_prefix = prefix + ("    " if is_last else "│   ")
            lines.append(f"{sub_prefix}💡 {node.get('discovery_reason')}")
        children = node.get("children") or []
        for idx, ch in enumerate(children):
            next_prefix = prefix + ("    " if is_last else "│   ")
            _walk(ch, next_prefix, idx == len(children) - 1)

    roots = tree_data.get("tree") or ([tree_data["root"]] if tree_data.get("root") else [])
    for idx, r in enumerate(roots):
        _walk(r, "", idx == len(roots) - 1)

    lines.append("=" * 78)
    return "\n".join(lines)


def run_calibration_benchmark(
    query: str = "matanshi",
    simulate: bool = True,
    auto_confirm_top_candidate: bool = True,
) -> dict[str, Any]:
    """Run the end-to-end Investigation Tree benchmark and return structured diagnostics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "bench_tree.db")
        store = Store(db_path)
        try:
            eid = store.resolve_entity("person", query, query, 1.0)
            profile = SearchTargetProfile.from_query(query, entity_id=eid)
            if not profile.usernames and " " not in query.strip():
                profile.usernames.append(query.strip().lstrip("@"))

            search_fn, http_fetcher, bytes_fetcher = (
                _build_simulated_environment(query) if simulate else (None, None, None)
            )

            job_id = f"bench_{query.strip().lstrip('@')}"
            engine = UnifiedReconEngine(
                store=store,
                http_fetcher=http_fetcher,
                search_fn=search_fn,
                max_depth=1,
            )
            recon_res = asyncio.run(
                engine.run_recon(
                    entity_id=eid,
                    profile=profile,
                    job_id=job_id,
                )
            )

            mgr = ReconJobManager(store)
            tree_before = store.get_investigation_tree(job_id=job_id, root_entity_id=eid)
            confirmed_res = None
            top_cands = tree_before.get("top3_candidates") or []
            if auto_confirm_top_candidate and top_cands:
                top_node_id = int(top_cands[0]["id"])
                confirmed_res = mgr.confirm_or_reject_candidate(
                    top_node_id,
                    decision="confirm",
                    auto_expand=True,
                    http_fetcher=http_fetcher,
                    bytes_fetcher=bytes_fetcher,
                )

            tree_after = store.get_investigation_tree(job_id=job_id, root_entity_id=eid)
            report_text = format_ascii_tree(tree_after)
            return {
                "ok": True,
                "query": query,
                "simulate": simulate,
                "findings_count": len(recon_res.get("findings") or []),
                "tree": tree_after,
                "confirmed_candidate": confirmed_res,
                "ascii_report": report_text,
            }
        finally:
            store.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Calibrate and benchmark the OSINT Investigation Tree.")
    parser.add_argument("--query", "-q", default="matanshi", help="Target username or name to investigate")
    parser.add_argument("--live", action="store_true", help="Run against live network instead of deterministic simulation")
    parser.add_argument("--simulate", action="store_true", default=True, help="Run deterministic multi-branch simulation (default)")
    args = parser.parse_args(argv)

    use_sim = not bool(args.live)
    res = run_calibration_benchmark(query=args.query, simulate=use_sim)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print(res["ascii_report"])
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
