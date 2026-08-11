"""Quick diagnostic script to isolate where [Errno 22] occurs in inference."""
import sys, os, traceback
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[4]
MODEL_BASE_PATH = BASE_DIR / "training" / "models" / "SecureBERT2.0-base"
ADAPTOR_ROOT = Path(__file__).resolve().parent / "weights" / "adapters"
ADAPTER_ID = "securebert-balanced-1to1"

print(f"[1] Base model path: {MODEL_BASE_PATH}")
print(f"    Exists: {MODEL_BASE_PATH.exists()}")
print(f"[2] Adapter path: {ADAPTOR_ROOT / ADAPTER_ID}")
print(f"    Exists: {(ADAPTOR_ROOT / ADAPTER_ID).exists()}")

# Step 1: Load tokenizer
try:
    from transformers import AutoTokenizer
    print("\n[3] Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_BASE_PATH), local_files_only=True)
    print("    Tokenizer loaded OK")
except Exception as e:
    print(f"    FAILED at tokenizer: {e}")
    traceback.print_exc()
    sys.exit(1)

# Step 2: Tokenize a test input
test_text = "invoke-virtual v0, Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;)V"
try:
    print(f"\n[4] Tokenizing test input ({len(test_text)} chars)...")
    inputs = tokenizer(
        test_text,
        padding="max_length",
        truncation=True,
        max_length=512,
        return_tensors="pt"
    )
    print(f"    Tokenized OK. input_ids shape: {inputs['input_ids'].shape}")
except Exception as e:
    print(f"    FAILED at tokenization: {e}")
    traceback.print_exc()
    sys.exit(1)

# Step 3: Load base model
try:
    from transformers import AutoModelForSequenceClassification
    print("\n[5] Loading base model (this may take a while for 596MB)...")
    base_model = AutoModelForSequenceClassification.from_pretrained(
        str(MODEL_BASE_PATH),
        num_labels=2,
        local_files_only=True
    )
    base_model.eval()
    print("    Base model loaded OK")
except Exception as e:
    print(f"    FAILED at base model load: {e}")
    traceback.print_exc()
    sys.exit(1)

# Step 4: Load PEFT adapter
try:
    from peft import PeftModel
    adapter_path = ADAPTOR_ROOT / ADAPTER_ID
    print(f"\n[6] Loading PEFT adapter from: {adapter_path}")
    active_model = PeftModel.from_pretrained(base_model, str(adapter_path))
    active_model.eval()
    print("    PEFT adapter loaded OK")
except Exception as e:
    print(f"    FAILED at PEFT adapter load: {e}")
    traceback.print_exc()
    sys.exit(1)

# Step 5: Run inference
try:
    import torch
    print("\n[7] Running inference...")
    with torch.no_grad():
        outputs = active_model(**inputs)
        logits = outputs.logits
        probs = torch.softmax(logits, dim=-1).squeeze().tolist()
        malicious_prob = probs[1] if isinstance(probs, list) and len(probs) > 1 else 0.0
        print(f"    Inference OK! Malicious probability: {malicious_prob:.4f}")
except Exception as e:
    print(f"    FAILED at inference: {e}")
    traceback.print_exc()
    sys.exit(1)

print("\n[SUCCESS] All steps completed without error.")
