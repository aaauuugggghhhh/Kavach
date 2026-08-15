import os
import sys
import torch
from pathlib import Path
from typing import List, Dict, Any, Optional
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from peft import PeftModel

BASE_DIR = Path(__file__).resolve().parents[4]  # Kavach root
MODEL_BASE_PATH = BASE_DIR / "training" / "models" / "SecureBERT2.0-base"
ADAPTOR_ROOT = Path(__file__).resolve().parent / "weights" / "adapters"

MODEL_METADATA = {
    "securebert-full-weighted": {
        "name": "SecureBERT Full Weighted (High Precision)",
        "description": "Trained on full dataset with weighted loss. Extremely low false-positive rate (99.6% precision)."
    },
    "securebert-balanced-1to1": {
        "name": "SecureBERT Balanced (High Recall)",
        "description": "Trained on 1:1 balanced subsample. High sensitivity/recall for catching subtle malware."
    }
}


def get_available_models() -> List[Dict[str, str]]:
    """Scans the adapters directory and returns metadata for available trained models."""
    models = []
    if ADAPTOR_ROOT.exists():
        for folder in ADAPTOR_ROOT.iterdir():
            if folder.is_dir() and ((folder / "adapter_model.safetensors").exists() or (folder / "adapter_model.bin").exists()):
                model_id = folder.name
                meta = MODEL_METADATA.get(model_id, {
                    "name": model_id.replace("-", " ").title(),
                    "description": f"Custom trained adapter: {model_id}"
                })
                models.append({
                    "id": model_id,
                    "name": meta["name"],
                    "description": meta["description"],
                    "path": str(folder)
                })
    
    # Fallback default if directory empty
    if not models:
        models.append({
            "id": "securebert-full-weighted",
            "name": "SecureBERT Full Weighted (Default)",
            "description": "Default High Precision Model",
            "path": str(ADAPTOR_ROOT / "securebert-full-weighted")
        })
    return models


class SecureBERTInferenceEngine:
    _instance = None
    _init_lock = __import__('threading').Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._init_lock:
                # Double-check inside lock to prevent race
                if cls._instance is None:
                    cls._instance = super(SecureBERTInferenceEngine, cls).__new__(cls)
                    cls._instance.initialized = False
                    cls._instance._adapter_lock = __import__('threading').Lock()
        return cls._instance

    def __init__(self):
        if self.initialized:
            return
        with self._init_lock:
            # Double-check inside lock
            if self.initialized:
                return
            
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            self.is_local = MODEL_BASE_PATH.exists()
            self.base_path = str(MODEL_BASE_PATH) if self.is_local else "cisco-ai/SecureBERT2.0-base"
            
            print(f"[ML Inference] Loading base SecureBERT model from: {self.base_path} on {self.device}")
            self.tokenizer = AutoTokenizer.from_pretrained(self.base_path, local_files_only=self.is_local)
            
            # Load with eager attention implementation to enable output_attentions=True (required for ModernBERT LRP)
            self.base_model = AutoModelForSequenceClassification.from_pretrained(
                self.base_path,
                num_labels=2,
                local_files_only=self.is_local,
                attn_implementation="eager"
            ).to(self.device)
            self.base_model.eval()

            self.current_adapter_id: Optional[str] = None
            self.active_model: Optional[PeftModel] = None
            self.initialized = True

    def load_adapter(self, model_id: str):
        """Loads or switches Peft adapter dynamically. Thread-safe."""
        if self.current_adapter_id == model_id and self.active_model is not None:
            return

        with self._adapter_lock:
            # Double-check inside lock
            if self.current_adapter_id == model_id and self.active_model is not None:
                return

            adapter_path = ADAPTOR_ROOT / model_id
            if not adapter_path.exists():
                avail = get_available_models()
                if avail:
                    adapter_path = Path(avail[0]["path"])
                    model_id = avail[0]["id"]
                else:
                    raise FileNotFoundError(f"Adapter model path not found: {adapter_path}")

            if self.active_model is None:
                print(f"[ML Inference] Initializing Peft model with adapter: {model_id} from {adapter_path}")
                self.active_model = PeftModel.from_pretrained(
                    self.base_model, 
                    str(adapter_path), 
                    adapter_name=model_id
                ).to(self.device)
            else:
                if model_id not in self.active_model.peft_config:
                    print(f"[ML Inference] Loading additional Peft adapter: {model_id} from {adapter_path}")
                    self.active_model.load_adapter(str(adapter_path), adapter_name=model_id)
                print(f"[ML Inference] Switching active Peft adapter to: {model_id}")
                self.active_model.set_adapter(model_id)

            self.active_model.eval()
            self.current_adapter_id = model_id

    def classify_slices(self, slices: List[str], model_id: str = "securebert-full-weighted") -> Dict[str, Any]:
        """Runs classification over extracted Dalvik program slices and computes Attention LRP relevance scores."""
        self.load_adapter(model_id)

        if not slices:
            return {
                "model_id": model_id,
                "verdict": "BENIGN",
                "malicious_probability": 0.05,
                "confidence_score": 0.95,
                "slice_count": 0,
                "slice_evaluations": []
            }

        slice_scores = []
        slice_evals = []

        # Hook to store intermediate attention probabilities from the eager model layers
        attention_probs_tensors = []

        def save_attn_probs(module, input, output):
            if isinstance(output, tuple) and len(output) > 1:
                attn_probs = output[1]
                if attn_probs is not None:
                    attn_probs.retain_grad()
                    attention_probs_tensors.append(attn_probs)

        # Register forward hooks on attention blocks
        hooks = []
        for name, module in self.active_model.named_modules():
            if "attention" in name.lower() or "attn" in name.lower():
                hooks.append(module.register_forward_hook(save_attn_probs))

        # Temporarily enable requires_grad on all parameters to track gradients through frozen layers for LRP
        original_requires_grad = {}
        for name, param in self.active_model.named_parameters():
            original_requires_grad[name] = param.requires_grad
            param.requires_grad = True

        try:
            for idx, code_slice in enumerate(slices[:15]): # Cap at top 15 slices for performance
                # Clear lists from previous loop iterations
                attention_probs_tensors.clear()

                inputs = self.tokenizer(
                    code_slice,
                    padding="max_length",
                    truncation=True,
                    max_length=128,  # Truncate to 128 for real-time inference latency
                    return_tensors="pt"
                ).to(self.device)

                # Forward pass tracking gradients for LRP backward calculation
                outputs = self.active_model(**inputs, output_attentions=True)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1).squeeze().tolist()
                
                malicious_prob = probs[1] if isinstance(probs, list) and len(probs) > 1 else 0.0
                slice_scores.append(malicious_prob)

                # Compute Attention LRP relevance backpropagation: R = (A * grad_A)^+
                relevance_tokens = []
                self.active_model.zero_grad()

                if logits.shape[0] > 0 and len(attention_probs_tensors) > 0:
                    score = logits[0, 1]
                    score.backward(retain_graph=True)
                    
                    last_layer_attn = attention_probs_tensors[-1]
                    if last_layer_attn.grad is not None:
                        relevance = torch.clamp(last_layer_attn * last_layer_attn.grad, min=0)
                        # Average relevance across attention heads: shape (seq, seq)
                        relevance_map = relevance[0].mean(dim=0)
                        # Sum over column to extract token importance weights: shape (seq,)
                        token_relevance = relevance_map.sum(dim=-1).tolist()
                        
                        # Translate input tokens and sanitize space prefixes
                        input_ids_list = inputs["input_ids"][0].tolist()
                        tokens = self.tokenizer.convert_ids_to_tokens(input_ids_list)
                        
                        for token, rel_val in zip(tokens, token_relevance):
                            if token not in ("<pad>", "[PAD]", "[CLS]", "[SEP]"):
                                clean_token = token.replace("Ġ", " ")
                                relevance_tokens.append([clean_token, round(rel_val, 6)])
                    
                # Format slice assessment payload
                slice_evals.append({
                    "slice_index": idx + 1,
                    "malicious_probability": round(malicious_prob, 4),
                    "code_snippet": code_slice[:200] + "..." if len(code_slice) > 200 else code_slice,
                    "relevance_tokens": relevance_tokens
                })
        finally:
            # Restore original requires_grad states to preserve training/adapter frozen boundaries
            for name, param in self.active_model.named_parameters():
                if name in original_requires_grad:
                    param.requires_grad = original_requires_grad[name]

            # Clean up all registered forward hooks to prevent PyTorch memory leaks
            for hook in hooks:
                hook.remove()

        max_prob = max(slice_scores) if slice_scores else 0.0
        mean_prob = sum(slice_scores) / len(slice_scores) if slice_scores else 0.0
        final_probability = round((max_prob * 0.7) + (mean_prob * 0.3), 4)

        verdict = "MALICIOUS" if final_probability >= 0.50 else "BENIGN"

        return {
            "model_id": model_id,
            "verdict": verdict,
            "malicious_probability": final_probability,
            "confidence_score": round(max(final_probability, 1 - final_probability), 4),
            "slice_count": len(slices),
            "slice_evaluations": slice_evals
        }
