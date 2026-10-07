import argparse
import json
import logging
import os
import signal
import sys
import time

from .config import Config
from .engine import Engine
from .ingest import import_path
from .render import render_tree
from .search import SearchService
from .store import Store
from .urls import normalize_url


def _setup(args):
    cfg = Config()
    if getattr(args, "db", None):
        cfg.db_path = args.db
    for k in ("workers", "delay"):
        v = getattr(args, k, None)
        if v is not None:
            setattr(cfg, {"delay": "request_delay"}.get(k, k), v)
    if getattr(args, "providers", None):
        cfg.providers = args.providers.split(",")
    if getattr(args, "follow_external", False):
        cfg.follow_external = True
    store = Store(cfg.db_path)
    eng = Engine(store, cfg)
    return cfg, store, eng, SearchService(eng)


def _seeds(eng, path, priority=10):
    n = 0
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            u = normalize_url(ln) if ln and not ln.startswith("#") else None
            if u:
                n += eng.store.add_source(u, priority=priority, origin="seed")[1]
    return n


def _wait_forever(eng):
    stop = []
    signal.signal(signal.SIGINT, lambda *a: stop.append(1))
    signal.signal(signal.SIGTERM, lambda *a: stop.append(1))
    while not stop:
        time.sleep(1)
    eng.stop()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="osnit", description="Continuous public-source OSINT engine")
    ap.add_argument("--db")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--workers", type=int)
    common.add_argument("--delay", type=float, help="min seconds between requests to one host")
    common.add_argument("--providers", help="comma list: wikipedia,searxng,brave,ddg")
    common.add_argument("--follow-external", action="store_true")

    s = sub.add_parser("serve", parents=[common], help="API + UI + background engine")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--seeds", help="file of seed URLs for the continuous crawl")
    s.add_argument("--open", action="store_true", help="open the UI in the default browser")
    s = sub.add_parser("run", parents=[common], help="headless 24/7 daemon")
    s.add_argument("--seeds")
    s = sub.add_parser("search", parents=[common], help="deep search from the terminal")
    s.add_argument("query")
    s.add_argument("--kind", choices=["person", "org", "email", "phone", "domain"])
    s.add_argument("--wait", type=float, default=0, help="seconds to keep scanning before printing the final picture")
    s.add_argument("--hours", type=float, help="how long the background search stays alive")
    s.add_argument("--json", action="store_true")
    s = sub.add_parser("import", help="import historical/public files or .jsonl dumps")
    s.add_argument("path")
    s.add_argument("--base-url")
    s.add_argument("--delete-raw", action="store_true", help="delete each source file after it was parsed")
    idb = sub.add_parser("import-db", help="import records from an earlier tool's database (sqlite/csv/tsv/json/jsonl)")
    idb.add_argument("path")
    idb.add_argument("--mapping", help="JSON file: {\"tables\": {\"<table>\": {\"name\": \"<col>\", ...}}}")
    idb.add_argument("--label", help="name shown as the source of these records")
    idb.add_argument("--trust", type=float, default=0.8, help="confidence given to these records (0-1)")
    idb.add_argument("--delete-raw", action="store_true", help="delete the input file after a successful import")
    idb.add_argument("--dry-run", action="store_true", help="only show which columns were recognised")
    an = sub.add_parser("analyze", help="stage 1 only: what a file holds (tables, column types, samples, overlap with the DB)")
    an.add_argument("path")
    an.add_argument("--json", action="store_true")
    rs = sub.add_parser("reset", help="delete data by origin: files | web | all")
    rs.add_argument("scope", choices=["files", "web", "all"])
    rs.add_argument("--yes", action="store_true", help="required: confirms the deletion")
    ty = sub.add_parser("add-type", help="teach a new information type (an ID you keep finding in files)")
    ty.add_argument("label")
    ty.add_argument("--headers", default="", help="comma list of column names it appears under")
    ty.add_argument("--examples", default="", help="comma list of example values (the pattern is learned from them)")
    ty.add_argument("--pattern", default="", help="or a regex for one value")
    ty.add_argument("--not-identifier", action="store_true", help="store as a field, do not link records with it")
    ty.add_argument("--sensitive", action="store_true", help="recognise but never store")
    ev = sub.add_parser("eval", help="measure extraction quality on a labelled corpus folder")
    ev.add_argument("folder")
    sub.add_parser("stats")
    fg = sub.add_parser("forget", help="erase an entity (name/email/phone/...) with its evidence (removal requests)")
    fg.add_argument("needle")
    show = sub.add_parser("show", help="print the current picture of an existing subject")
    show.add_argument("subject_id", type=int)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(message)s")
    cfg, store, eng, svc = _setup(args)

    if args.cmd == "stats":
        print(json.dumps(store.stats(), ensure_ascii=False, indent=2))
    elif args.cmd == "import-db":
        from .importdb import import_db, read_tables
        mapping = json.load(open(args.mapping, encoding="utf-8")) if args.mapping else None
        if args.dry_run:
            from .importdb import Context
            for table, plan, _rows in read_tables(args.path, mapping, Context(store), all_tables=True):
                print(f"{table}:")
                for c in plan.columns:
                    print(f"  {c.name:<24} {c.status:<10} {c.label} ({c.how}, {round(c.confidence * 100)}%)")
        else:
            res = import_db(eng, args.path, mapping, args.label, args.trust, args.delete_raw or cfg.delete_imported,
                            progress=lambda s: logging.info("imported %d records", s["records"]))
            print(json.dumps(res, ensure_ascii=False))
    elif args.cmd == "analyze":
        from .analyze import analyze_file
        a = analyze_file(store, args.path)
        if args.json:
            print(json.dumps(a, ensure_ascii=False, indent=1, default=str))
        else:
            print(f"{a['file']}: {a['records']} records in {len(a['tables'])} table(s)")
            print("information types: " + ", ".join(("🔗 " if t["linkable"] else "") + t["label"] for t in a["info_types"]))
            if a["sensitive"]:
                print("sensitive (not stored): " + ", ".join(x["column"] for x in a["sensitive"]))
            for t in a["tables"]:
                print(f"\n[{t['table']}] {t['rows']} rows")
                for c in t["columns"]:
                    print(f"  {c['name']:<24} {c['status']:<10} {c['label']} ({c['how']}, {round(c['confidence'] * 100)}%)"
                          f"  e.g. {' | '.join(c['samples'][:2])}")
            for k in a["known"]["examples"]:
                print(f"already known: {k['value']} -> {', '.join(o['name'] for o in k['owners'])} ({', '.join(k['seen_in'])})")
    elif args.cmd == "reset":
        if not args.yes:
            sys.exit("refusing without --yes")
        print(json.dumps(store.reset(args.scope), ensure_ascii=False))
    elif args.cmd == "add-type":
        from .semantic import CustomType, custom_key, pattern_from_examples
        ex = [x.strip() for x in args.examples.split(",") if x.strip()]
        pat = args.pattern or pattern_from_examples(ex)
        key = custom_key(args.label)
        store.save_custom_type(key, args.label, [h.strip() for h in args.headers.split(",") if h.strip()], pat, ex,
                               not args.not_identifier, args.sensitive)
        ct = CustomType(key, args.label, (), pat)
        print(json.dumps(dict(key=key, pattern=pat, examples={x: ct.matches(x) for x in ex}), ensure_ascii=False))
    elif args.cmd == "eval":
        from .evaluate import evaluate
        summary, docs = evaluate(args.folder)
        for d in docs:
            bad = {k: d[k] for k in ("persons_fp", "persons_fn", "links_missing", "violations", "over_confident") if d[k]}
            print(f"{d['doc']}: page={d['page_type']} links={d['links_found']}" + (f"  {json.dumps(bad, ensure_ascii=False)}" if bad else ""))
        print(json.dumps(summary, ensure_ascii=False))
    elif args.cmd == "forget":
        print(json.dumps(store.forget(args.needle), ensure_ascii=False))
    elif args.cmd == "show":
        print(render_tree(svc.profile(args.subject_id)))
    elif args.cmd == "import":
        print(json.dumps(import_path(eng, args.path, args.base_url, args.delete_raw or cfg.delete_imported),
                         ensure_ascii=False))
    elif args.cmd == "search":
        res = svc.search(args.query, args.kind, args.hours)
        sid = res["subject_id"]
        if not args.json:
            print("— תוצאה ראשונית (מהמאגר הקיים) —")
            print(render_tree(res["profile"]))
        if args.wait:
            eng.start()
            end = time.time() + args.wait
            try:
                while time.time() < end:
                    time.sleep(2)
            except KeyboardInterrupt:
                pass
            eng.stop()
            res["profile"] = svc.profile(sid)
            if not args.json:
                print("\n— תמונה מעודכנת —")
        print(json.dumps(res["profile"], ensure_ascii=False, indent=1) if args.json else render_tree(res["profile"]))
    elif args.cmd in ("serve", "run"):
        if args.seeds:
            logging.info("seeded %d urls", _seeds(eng, args.seeds))
        eng.start()
        from .importqueue import ImportQueue
        queue = ImportQueue(eng, inbox=os.path.join(os.path.dirname(cfg.db_path) or ".", "inbox"))
        queue.start()
        logging.info("import inbox: %s", queue.inbox)
        if args.cmd == "serve":
            from .server import make_server, serve_in_thread
            srv = make_server(svc, args.host, args.port, os.environ.get("OSNIT_TOKEN"), queue=queue)
            serve_in_thread(srv)
            logging.info("UI on http://%s:%d", args.host, args.port)
            if args.open:
                import webbrowser
                webbrowser.open(f"http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.port}/")
        _wait_forever(eng)


if __name__ == "__main__":
    sys.exit(main())
