from .cli import main

if __name__ == "__main__":      # import-worker processes (spawn, Windows) re-import this module: never re-run the CLI
    main()
