"""Evaluation metrics for CyberSentinel training reports."""

from __future__ import annotations

from typing import Dict, List, Optional

import numpy as np


def _safe_div(numerator: float, denominator: float) -> float:
    return float(numerator / denominator) if denominator > 0 else 0.0


def evaluate_supervised(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray],
    class_names: List[str],
) -> Dict:
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    all_labels = list(range(len(class_names)))
    present_classes = sorted(set(y_true.tolist()) | set(y_pred.tolist()))

    metrics: Dict = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", labels=all_labels, zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", labels=all_labels, zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", labels=all_labels, zero_division=0)),
        "precision_weighted": float(precision_score(y_true, y_pred, average="weighted", labels=all_labels, zero_division=0)),
        "recall_weighted": float(recall_score(y_true, y_pred, average="weighted", labels=all_labels, zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", labels=all_labels, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=all_labels).tolist(),
        "confusion_matrix_labels": class_names,
        "classes_in_dataset": {
            "present_class_indices": present_classes,
            "present_class_names": [class_names[i] for i in present_classes if i < len(class_names)],
            "missing_class_names": [class_names[i] for i in all_labels if i not in present_classes],
        },
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=all_labels,
            target_names=class_names,
            zero_division=0,
            output_dict=True,
        ),
    }

    if y_proba is not None and y_proba.ndim == 2:
        try:
            metrics["roc_auc_macro"] = float(roc_auc_score(y_true, y_proba, multi_class="ovr", average="macro"))
            metrics["roc_auc_weighted"] = float(roc_auc_score(y_true, y_proba, multi_class="ovr", average="weighted"))
        except ValueError as exc:
            metrics["roc_auc_macro"] = None
            metrics["roc_auc_weighted"] = None
            metrics["roc_auc_error"] = str(exc)

        per_class_auc = {}
        for idx, name in enumerate(class_names):
            y_binary = (y_true == idx).astype(int)
            if len(np.unique(y_binary)) < 2:
                per_class_auc[name] = None
                continue
            try:
                per_class_auc[name] = float(roc_auc_score(y_binary, y_proba[:, idx]))
            except ValueError:
                per_class_auc[name] = None
        metrics["roc_auc_per_class"] = per_class_auc

    y_true_bin = (y_true != 0).astype(int)
    y_pred_bin = (y_pred != 0).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1]).ravel()

    binary = {
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "false_positive_rate": round(_safe_div(fp, fp + tn), 4),
        "false_negative_rate": round(_safe_div(fn, fn + tp), 4),
        "true_positive_rate": round(_safe_div(tp, tp + fn), 4),
        "specificity": round(_safe_div(tn, tn + fp), 4),
        "precision_attack": round(_safe_div(tp, tp + fp), 4),
        "recall_attack": round(_safe_div(tp, tp + fn), 4),
    }

    if y_proba is not None and y_proba.shape[1] > 0:
        attack_score = 1.0 - y_proba[:, 0]
        try:
            binary["roc_auc"] = float(roc_auc_score(y_true_bin, attack_score))
        except ValueError:
            binary["roc_auc"] = None

    metrics["binary_attack_detection"] = binary
    return metrics


def evaluate_unsupervised(
    y_true: np.ndarray,
    anomaly_pred: np.ndarray,
    anomaly_scores: Optional[np.ndarray] = None,
) -> Dict:
    from sklearn.metrics import roc_auc_score

    y_true_anomaly = (y_true != 0).astype(int)
    anomaly_bin = anomaly_pred.astype(int)

    tn = int(((y_true_anomaly == 0) & (anomaly_bin == 0)).sum())
    fp = int(((y_true_anomaly == 0) & (anomaly_bin == 1)).sum())
    fn = int(((y_true_anomaly == 1) & (anomaly_bin == 0)).sum())
    tp = int(((y_true_anomaly == 1) & (anomaly_bin == 1)).sum())

    metrics = {
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "false_positive_rate": round(_safe_div(fp, fp + tn), 4),
        "false_negative_rate": round(_safe_div(fn, fn + tp), 4),
        "true_positive_rate": round(_safe_div(tp, tp + fn), 4),
        "specificity": round(_safe_div(tn, tn + fp), 4),
        "precision": round(_safe_div(tp, tp + fp), 4),
        "recall": round(_safe_div(tp, tp + fn), 4),
    }

    if anomaly_scores is not None:
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true_anomaly, anomaly_scores))
        except ValueError:
            metrics["roc_auc"] = None

    return metrics
