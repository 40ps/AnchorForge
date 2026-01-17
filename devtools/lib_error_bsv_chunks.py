import logging
import sys
from bsv import Script

# Configure simple logging to stdout
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("repro")

def analyze_with_library_chunks(script: Script):
    """
    ATTEMPT A: Using the library's built-in .chunks iterator.
    This is expected to fail or produce incorrect opcodes for '006a...' scripts.
    """
    logger.info("\n--- METHOD A: Library .chunks Iterator (The Issue) ---")
    
    if not hasattr(script, 'chunks'):
        logger.error("Script object has no 'chunks' attribute.")
        return

    try:
        # Iterating over chunks triggers the library's parsing logic
        for i, chunk in enumerate(script.chunks):
            op = chunk.op
            data = chunk.data
            
            # Diagnostic output of what the library "thinks" this chunk is
            op_display = hex(op) if isinstance(op, int) else str(op)
            data_display = data.hex() if data else "None"
            
            logger.info(f"  Chunk {i}: OP={op_display} (Type: {type(op).__name__}), Data={data_display}")
            
    except Exception as e:
        logger.error(f"  CRASH during chunk iteration: {e}")
        # In a bug report, the stack trace is valuable, but for this output we keep it clean.
        # import traceback; traceback.print_exc() 


def analyze_with_manual_parsing(script: Script):
    """
    ATTEMPT B: Manual Byte-Level Parsing.
    This logic mimics a manual parser (like in my working project verifier) 
    that bypasses the .chunks iterator.
    """
    logger.info("\n--- METHOD B: Manual Byte Parsing (Working Workaround) ---")
    
    try:
        # 1. Get raw bytes directly
        raw_bytes = bytes.fromhex(script.hex())
        logger.info(f"  Raw Hex: {script.hex()}")

        i = 0
        element_count = 0
        
        while i < len(raw_bytes):
            byte = raw_bytes[i]
            i += 1
            
            # Simple parser logic for demonstration
            if byte == 0x00:
                logger.info(f"  Element {element_count}: OP_FALSE (0x00)")
            elif byte == 0x6a:
                logger.info(f"  Element {element_count}: OP_RETURN (0x6a)")
            
            # Handle Data Pushes (Simplified for demo)
            elif 0x01 <= byte <= 0x4b:
                # Direct push 1-75 bytes
                length = byte
                data = raw_bytes[i : i + length]
                i += length
                logger.info(f"  Element {element_count}: PUSH ({length} bytes) -> {data.hex()}")
                
            elif byte == 0x4c: # PUSHDATA1
                length = raw_bytes[i]
                i += 1
                data = raw_bytes[i : i + length]
                i += length
                logger.info(f"  Element {element_count}: PUSHDATA1 ({length} bytes) -> {data.hex()}")
                
            # (Omitted PUSHDATA2/4 for brevity in repro script)
            
            else:
                 logger.info(f"  Element {element_count}: OP_{hex(byte)}")
            
            element_count += 1

    except Exception as e:
        logger.error(f"Error in manual parsing: {e}")


def main():
    print("=========================================================")
    print(" Reproduction: bsv-sdk Script.chunks behavior on 0x006a ")
    print("=========================================================")

    # Test Case: "Safe OP_RETURN"
    # 00 (OP_FALSE) 
    # 6a (OP_RETURN) 
    # 04 (Push 4 bytes) 
    # 54657374 ("Test")
    hex_string = "006a0454657374"
    
    print(f"Input Script Hex: {hex_string}")
    
    # Create Script Object
    script = Script(hex_string)
    
    # 1. Run the failing/problematic version
    analyze_with_library_chunks(script)
    
    # 2. Run the working workaround
    analyze_with_manual_parsing(script)

if __name__ == "__main__":
    main()