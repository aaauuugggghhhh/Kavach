# Serious SecureBERT training handoff

Run the two experiments sequentially on one CUDA GPU. Do not use or evaluate the test split.

**Weighted CE affects TRAINING LOSS ONLY. Validation loss and all validation metrics remain ordinary/unweighted.** Both experiments evaluate the same natural validation membership.

## 1. Check the GPU

```bash
.venv/bin/python -c "import torch; print('torch', torch.__version__); print('cuda', torch.cuda.is_available()); print('gpu', torch.cuda.get_device_name(0) if torch.cuda.is_available() else None); print('vram_bytes', torch.cuda.get_device_properties(0).total_memory if torch.cuda.is_available() else None); print('bf16', torch.cuda.is_bf16_supported() if torch.cuda.is_available() else False)"
```

The committed configs conservatively use FP32. If BF16 is supported, verify it with a short approved hardware check before changing both serious configs to BF16. Otherwise use verified CUDA FP16, or retain FP32. Apply the same precision to both runs.

Microbatch size may be changed for VRAM, but keep effective batch size near 16 and use the same setting for both runs: `2 x 8`, `4 x 4`, or `8 x 2`. Do not change learning rate, epochs, context length, sampling, loss policy, or validation membership. Config changes are captured in provenance.

## 2. Run balanced training first

```bash
.venv/bin/python training/train.py --config training/configs/train_balanced_1to1.yaml
```

This uses 7,661 malicious and 7,661 deterministically cycling benign slices per epoch, ordinary CE, and natural validation.

Before continuing, inspect the output run manifest, `metrics.json`, `trainer_state.json`, checkpoints, final adapter, logs, and offline W&B directory. Report lifecycle status, NaN/Inf checks, device/precision, runtime/throughput, best epoch, train/eval losses, malicious precision/recall/F1, TN/FP/FN/TP, and all warnings or errors.

**STOP if lifecycle is not completed, loss or metrics contain NaN/Inf, validation failed, or checkpoints/final adapter are missing. Do not automatically start run 2.**

## 3. Run full weighted training after approval

```bash
.venv/bin/python training/train.py --config training/configs/train_full_weighted.yaml
```

This uses all 58,970 eligible training slices exactly once per epoch. Training CE uses weights derived only from the finalized training counts; validation loss and metrics remain ordinary and unweighted. Repeat the complete inspection above after it finishes.
