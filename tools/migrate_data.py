import os
import shutil
from pathlib import Path

# --- Definition der neuen Struktur (Config V2.1) ---
BASE_DIR = Path(".")

# Ziel-Verzeichnisse
OUTPUT_DIR = BASE_DIR / "output"
DATABASE_DIR = BASE_DIR / "database"        # Nur noch für tx_store
WALLET_CACHE_DIR = BASE_DIR / "cache" / "wallet"  # Für UTXOs (Privat)
PUBLIC_CACHE_DIR = BASE_DIR / "cache" / "public"  # Für Header (Öffentlich)
RUNTIME_DIR = BASE_DIR / "runtime"

def ensure_directories():
    """Erstellt die Zielverzeichnisse, falls sie fehlen."""
    for d in [DATABASE_DIR, WALLET_CACHE_DIR, PUBLIC_CACHE_DIR, OUTPUT_DIR, RUNTIME_DIR]:
        if not d.exists():
            print(f"Erstelle Verzeichnis: {d}")
            d.mkdir(parents=True, exist_ok=True)

def move_files_by_pattern(source_dir: Path, pattern: str, dest_dir: Path, description: str):
    """Verschiebt Dateien, die einem Muster entsprechen, in das Zielverzeichnis."""
    if not source_dir.exists():
        return

    # Suche im Quellverzeichnis
    files = list(source_dir.glob(pattern))
    files = [f for f in files if f.is_file()]

    if not files:
        return

    print(f"\n--- Verschiebe {description} ---")
    print(f"    Von:  {source_dir}")
    print(f"    Nach: {dest_dir}")
    
    for src in files:
        # Verhindere Verschieben, wenn Quelle == Ziel
        if src.parent.resolve() == dest_dir.resolve():
            print(f" ℹ️  {src.name} liegt bereits richtig.")
            continue

        dst = dest_dir / src.name
        
        try:
            shutil.move(str(src), str(dst))
            print(f" ✅ {src.name}")
        except Exception as e:
            print(f" ❌ Fehler bei {src.name}: {e}")

def main():
    print("==========================================================")
    print("   ANCHORFORGE DATEN-MIGRATION (V2.1 -> Split Cache)")
    print("==========================================================")
    
    ensure_directories()

    # 1. Block-Header: Von 'database/' (oder root) nach 'cache/public/'
    move_files_by_pattern(BASE_DIR / "database", "block_headers_*.json", PUBLIC_CACHE_DIR, "Block-Header (aus DB)")
    move_files_by_pattern(BASE_DIR, "block_headers_*.json", PUBLIC_CACHE_DIR, "Block-Header (aus Root)")

    # 2. UTXOs: Von 'cache/' (alt) nach 'cache/wallet/' (neu)
    #    Behandelt auch _invalid.json Dateien
    old_cache_dir = BASE_DIR / "cache"
    move_files_by_pattern(old_cache_dir, "utxo_store_*.json", WALLET_CACHE_DIR, "UTXO-Stores")
    move_files_by_pattern(old_cache_dir, "used_utxo_store_*.json", WALLET_CACHE_DIR, "Verbrauchte UTXOs")
    
    # Falls noch im Root liegend (Sicherheitsnetz)
    move_files_by_pattern(BASE_DIR, "utxo_store_*.json", WALLET_CACHE_DIR, "UTXO-Stores (aus Root)")
    move_files_by_pattern(BASE_DIR, "used_utxo_store_*.json", WALLET_CACHE_DIR, "Verbrauchte UTXOs (aus Root)")

    # 3. Transaktions-Stores: Bleiben in 'database/' (Sicherstellen, dass sie da sind)
    move_files_by_pattern(BASE_DIR, "tx_store_*.json", DATABASE_DIR, "TX-Stores (aus Root)")

    # 4. Logs & Runtime: Wie gehabt aufräumen
    move_files_by_pattern(BASE_DIR, "audit_log_*.json", OUTPUT_DIR, "Audit-Logs")
    move_files_by_pattern(BASE_DIR, "*.log", OUTPUT_DIR, "Logs")
    move_files_by_pattern(BASE_DIR, "*_batch_status.json", RUNTIME_DIR, "Status-Dateien")
    move_files_by_pattern(BASE_DIR, "*.flag", RUNTIME_DIR, "Flag-Dateien")

    print("\n==========================================================")
    print(" Migration abgeschlossen.")
    print("==========================================================")
    print("Struktur:")
    print(f" [Privat]  Wallet Cache: {WALLET_CACHE_DIR}  (UTXOs)")
    print(f" [Privat]  Database:     {DATABASE_DIR}      (TX History)")
    print(f" [Public]  Public Cache: {PUBLIC_CACHE_DIR}  (Block Headers)")
    print(f" [Output]  Output:       {OUTPUT_DIR}        (Logs)")

if __name__ == "__main__":
    main()