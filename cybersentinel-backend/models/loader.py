"""
models/loader.py

Loads CyberSentinel ML models at startup (cs-fyp XGBoost engine only).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

from core.config import settings


DEFAULT_PACKET_MODEL_TYPE = "xgboost"
DEFAULT_CLUSTERING_ALGORITHM = "kmeans"
CLUSTERING_ALGORITHMS = ("kmeans", "dbscan")

XGB_ARTIFACTS = (
    "supervised_model.joblib",
    "scaler.joblib",
    "unsupervised_model.joblib",
    "training_report.json",
)


@dataclass
class ModelRegistry:
    """Holds references to every loaded ML model."""

    packet_classifier: object | None = field(default=None, repr=False)
    packet_anomaly_detector: object | None = field(default=None, repr=False)
    firewall_pipelines: dict[str, object] = field(default_factory=dict, repr=False)
    firewall_pipeline: object | None = field(default=None, repr=False)

    packet_classifier_available: bool = False
    packet_anomaly_available: bool = False
    firewall_pipeline_available: bool = False

    packet_classifier_meta: dict = field(default_factory=dict)
    packet_anomaly_meta: dict = field(default_factory=dict)
    firewall_pipeline_meta: dict = field(default_factory=dict)

    @classmethod
    async def load(cls) -> "ModelRegistry":
        registry = cls()
        await registry._load_packet_classifier()
        await registry._load_packet_anomaly_detector()
        await registry._load_firewall_pipelines()
        registry._log_summary()
        return registry

    async def _load_packet_classifier(self) -> None:
        model_dir = settings.SUPERVISED_MODEL_DIR
        supervised = model_dir / "supervised_model.joblib"
        scaler = model_dir / "scaler.joblib"

        if not supervised.exists() or not scaler.exists():
            logger.warning(
                "XGBoost packet classifier artifacts not found in {path}. "
                "Run scripts/train_models.py from the repo root.",
                path=model_dir,
            )
            return

        try:
            from ml_engine.xgb_classifier import CyberSentinelXGBClassifier

            logger.info("Loading XGBoost packet classifier (cs-fyp engine)...")
            classifier = CyberSentinelXGBClassifier.load_model(model_dir)
            self.packet_classifier = classifier
            self.packet_classifier_available = True
            self.packet_classifier_meta = {
                "engine": "cs-fyp_xgboost",
                "model_type": DEFAULT_PACKET_MODEL_TYPE,
                "accuracy": getattr(classifier.training_report, "accuracy", None),
                "f1_weighted": getattr(classifier.training_report, "f1_weighted", None),
                "classes": getattr(classifier.training_report, "classes", []),
            }
            logger.success("XGBoost packet classifier loaded.")
        except Exception as exc:
            logger.error("Failed to load XGBoost classifier: {error}", error=exc)
            if "xgboost" in str(exc).lower() or exc.__class__.__name__ == "ModuleNotFoundError":
                logger.error(
                    "Install xgboost in this Python environment: pip install xgboost "
                    "(or run cybersentinel-backend via .venv/Scripts/python.exe run.py)"
                )
            self.packet_classifier = None
            self.packet_classifier_available = False

    async def _load_packet_anomaly_detector(self) -> None:
        model_dir = settings.SUPERVISED_MODEL_DIR
        unsupervised = model_dir / "unsupervised_model.joblib"
        scaler = model_dir / "scaler.joblib"

        if not unsupervised.exists() or not scaler.exists():
            logger.warning(
                "Packet anomaly artifacts not found in {path}. "
                "Run scripts/train_models.py to train unsupervised_model.joblib.",
                path=model_dir,
            )
            return

        try:
            from ml_engine.xgb_classifier import XGBPacketAnomalyDetector

            logger.info("Loading Isolation Forest packet anomaly detector (cs-fyp engine)...")
            self.packet_anomaly_detector = XGBPacketAnomalyDetector.load(model_dir)
            self.packet_anomaly_available = True
            self.packet_anomaly_meta = getattr(self.packet_anomaly_detector, "metadata", {})
            logger.success("Packet anomaly detector loaded.")
        except Exception as exc:
            logger.error("Failed to load packet anomaly detector: {error}", error=exc)
            self.packet_anomaly_detector = None
            self.packet_anomaly_available = False

    async def _load_firewall_pipelines(self) -> None:
        anomaly_path = settings.anomaly_model_path
        if not anomaly_path.exists():
            logger.warning(
                "Unsupervised anomaly model not found: {path}. "
                "Run unsupervised_learning/train.py first.",
                path=anomaly_path,
            )
            return

        try:
            _add_to_sys_path(settings.UNSUPERVISED_MODEL_DIR.parent.parent / "unsupervised_learning")
            from pipeline import UnsupervisedPipeline
            from config import PipelineConfig

            for algorithm in CLUSTERING_ALGORITHMS:
                clustering_path = settings.clustering_model_path_for(algorithm)
                legacy_cluster = settings.clustering_model_path
                if not clustering_path.exists():
                    if algorithm == DEFAULT_CLUSTERING_ALGORITHM and legacy_cluster.exists():
                        clustering_path = legacy_cluster
                    else:
                        continue

                config = PipelineConfig(
                    model_dir=str(settings.UNSUPERVISED_MODEL_DIR),
                    anomaly_model_filename=anomaly_path.name,
                    clustering_model_filename=clustering_path.name,
                    clustering_algorithm=algorithm,
                )
                logger.info(
                    "Loading unsupervised firewall pipeline (clustering={algorithm})...",
                    algorithm=algorithm,
                )
                pipeline = UnsupervisedPipeline(config)
                pipeline.load_pipeline(clustering_path=str(clustering_path))
                self.firewall_pipelines[algorithm] = pipeline

            if not self.firewall_pipelines:
                raise FileNotFoundError("No clustering model artifacts could be loaded.")

            self.firewall_pipeline = self.firewall_pipelines.get(
                DEFAULT_CLUSTERING_ALGORITHM,
                next(iter(self.firewall_pipelines.values())),
            )
            self.firewall_pipeline_available = True
            default_pipeline = self.firewall_pipeline
            self.firewall_pipeline_meta = {
                "available_clustering_algorithms": sorted(self.firewall_pipelines.keys()),
                "default_clustering_algorithm": DEFAULT_CLUSTERING_ALGORITHM,
                "anomaly_model": getattr(default_pipeline.anomaly_model, "metadata", {}),
                "clustering_model": getattr(default_pipeline.cluster_model, "metadata", {}),
            }
            logger.success(
                "Unsupervised firewall pipelines loaded: {algorithms}",
                algorithms=", ".join(sorted(self.firewall_pipelines.keys())),
            )
        except Exception as exc:
            logger.error("Failed to load unsupervised firewall pipeline: {error}", error=exc)
            self.firewall_pipelines = {}
            self.firewall_pipeline = None
            self.firewall_pipeline_available = False

    def _log_summary(self) -> None:
        logger.info("=" * 55)
        logger.info("CyberSentinel ML Model Registry — startup summary")
        logger.info("=" * 55)
        _status(self.packet_classifier_available, "XGBoost packet classifier")
        _status(self.packet_anomaly_available, "Packet anomaly detector (Isolation Forest)")
        _status(self.firewall_pipeline_available, "Unsupervised firewall pipeline")
        logger.info("=" * 55)

    async def reload(self) -> None:
        logger.info("Reloading all ML models from disk...")
        self.packet_classifier = None
        self.packet_classifier_available = False
        self.packet_anomaly_detector = None
        self.packet_anomaly_available = False
        self.firewall_pipelines = {}
        self.firewall_pipeline = None
        self.firewall_pipeline_available = False
        await self._load_packet_classifier()
        await self._load_packet_anomaly_detector()
        await self._load_firewall_pipelines()
        self._log_summary()

    def require_packet_classifier(self, model_type: str | None = None) -> object:
        if model_type and model_type != DEFAULT_PACKET_MODEL_TYPE:
            logger.debug(
                "Ignoring model_type={type!r}; only xgboost is supported.",
                type=model_type,
            )
        if self.packet_classifier is not None:
            return self.packet_classifier
        raise ModelNotAvailableError(
            "XGBoost packet classifier is not loaded. "
            "Train artifacts with scripts/train_models.py then restart the server."
        )

    def get_packet_anomaly_detector(self) -> object | None:
        return self.packet_anomaly_detector

    def require_firewall_pipeline(self, clustering_algorithm: str | None = None) -> object:
        requested = clustering_algorithm or DEFAULT_CLUSTERING_ALGORITHM
        if requested in self.firewall_pipelines:
            return self.firewall_pipelines[requested]
        if DEFAULT_CLUSTERING_ALGORITHM in self.firewall_pipelines:
            return self.firewall_pipelines[DEFAULT_CLUSTERING_ALGORITHM]
        if self.firewall_pipelines:
            return next(iter(self.firewall_pipelines.values()))
        raise ModelNotAvailableError(
            "Unsupervised firewall pipeline is not loaded. "
            "Train the model first by running unsupervised_learning/train.py "
            "then restart the server."
        )


class ModelNotAvailableError(RuntimeError):
    """Raised when a required ML model has not been loaded."""


def _add_to_sys_path(path: Path) -> None:
    str_path = str(path.resolve())
    if str_path not in sys.path:
        sys.path.insert(0, str_path)


def _status(available: bool, name: str) -> None:
    if available:
        logger.success("  ✓  {name}", name=name)
    else:
        logger.warning("  ✗  {name}  — NOT LOADED", name=name)
