# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    transfer.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# could be moved to bank functionls later on
import logging
from typing import Optional, Dict, Any, cast

from bsv import (
    PrivateKey,
    P2PKH,
    Transaction,
    TransactionInput,
    TransactionOutput,
    SatoshisPerKilobyte,
    UnlockingScriptTemplate,
)

from anchorforge.config import Config
from anchorforge import blockchain_api

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper: normalize UTXO formats (WOC / alt explorers)
# ---------------------------------------------------------------------------

def _normalize_utxo(u: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Normalize various UTXO formats to:
      {
        txid: str,
        vout: int,
        satoshis: int,
        height: int (optional, -1 if unknown)
      }

    Supported input variants:
      - { txid, vout, satoshis }
      - { tx_hash, tx_pos, value }
    """

    txid = u.get("txid") or u.get("tx_hash")
    vout = u.get("vout")
    if vout is None:
        vout = u.get("tx_pos")

    sats = u.get("satoshis")
    if sats is None:
        sats = u.get("value")

    if txid is None or vout is None or sats is None:
        return None

    return {
        "txid": str(txid),
        "vout": int(vout),
        "satoshis": int(sats),
        "height": int(u.get("height", -1)) if u.get("height") is not None else -1,
    }


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------

async def sweep_funds(
    private_key_wif: str,
    destination_address:str,
    broadcast: bool = True,
    min_output_sats: int = 546,
) -> Optional[Dict[str, Any]]:
    """
    Sweeps all UTXOs of the address derived from `private_key_wif`
    to Config.BANK_ADDRESS (inputs minus fee).

    Network (testnet/mainnet) is taken automatically from Config /.env.
    """

    assert Config.BANK_ADDRESS is not None, "BANK_ADDRESS missing in .env"

    # ---------------------------------------------------------------------
    # Key + addresses
    # ---------------------------------------------------------------------

    priv_key = PrivateKey(private_key_wif, network=Config.ACTIVE_NETWORK_BSV)
    sender_address = str(priv_key.address())

    logger.info("--- Sweep to Bank ---")
    logger.info(f"Network:        {Config.ACTIVE_NETWORK_NAME}")
    logger.info(f"Source address: {sender_address}")
    logger.info(f"Bank address:   {destination_address}")

    # ---------------------------------------------------------------------
    # Fetch + normalize UTXOs
    # ---------------------------------------------------------------------

    utxos  = await blockchain_api.fetch_normalized_utxos_for_address(sender_address)
    if not utxos:
        logger.warning(f"No utxos fond for {sender_address}")
        return None

    # ---------------------------------------------------------------------
    # Build inputs
    # ---------------------------------------------------------------------

    tx_inputs = []
    total_input_sats = 0

    for utxo in utxos:
        raw_source_tx_hex = await blockchain_api.fetch_raw_transaction_hex(
            utxo["txid"]
        )
        if not raw_source_tx_hex:
            logger.warning(
                f"Skipping {utxo['txid']}:{utxo['vout']} (missing source tx)"
            )
            continue

        source_tx_obj = Transaction.from_hex(raw_source_tx_hex)

        tx_inputs.append(
            TransactionInput(
                source_transaction=source_tx_obj,
                source_txid=utxo["txid"],
                source_output_index=utxo["vout"],
                unlocking_script_template=cast(
                    UnlockingScriptTemplate,
                    P2PKH().unlock(priv_key),
                ),
            )
        )

        total_input_sats += utxo["satoshis"]

    if not tx_inputs:
        logger.error("No valid inputs after source-tx fetch.")
        return None

    # ---------------------------------------------------------------------
    # Single output to bank (change=True = inputs - fee)
    # ---------------------------------------------------------------------

    bank_output = TransactionOutput(
        locking_script=P2PKH().lock(destination_address),
        change=True,
    )

    tx = Transaction(tx_inputs, [bank_output])

    # Fee calculation
    tx.fee(SatoshisPerKilobyte(value=Config.FEE_STRATEGY))

    total_output_sats = sum(o.satoshis for o in tx.outputs)
    fee_sats = total_input_sats - total_output_sats
    bank_out_sats = tx.outputs[0].satoshis if tx.outputs else 0

    logger.info(f"Inputs total: {total_input_sats} sats")
    logger.info(f"Bank output:  {bank_out_sats} sats")
    logger.info(f"Fee:          {fee_sats} sats")

    if total_input_sats <= fee_sats:
        logger.error("Insufficient funds to cover fee.")
        return None

    if 0 < bank_out_sats < min_output_sats:
        logger.error(
            f"Dust output: {bank_out_sats} sats < {min_output_sats}"
        )
        return None

    # ---------------------------------------------------------------------
    # Sign + broadcast
    # ---------------------------------------------------------------------

    tx.sign()
    tx_hex = tx.hex()
    txid_local = tx.txid()

    txid_broadcast = None
    if broadcast:
        txid_broadcast = await blockchain_api.broadcast_transaction(tx_hex)
        if not txid_broadcast:
            logger.error("Broadcast failed.")

    return {
        "network": Config.ACTIVE_NETWORK_NAME,
        "source_address": sender_address,
        "destination_address": destination_address,
        "txid": txid_broadcast or txid_local,
        "txid_local": txid_local,
        "broadcasted": bool(txid_broadcast) if broadcast else False,
        "tx_hex": tx_hex,
        "total_input_sats": total_input_sats,
        "bank_output_sats": bank_out_sats,
        "fee_sats": fee_sats,
        "num_inputs": len(tx_inputs),
    }
