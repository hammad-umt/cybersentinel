"""
models/loader.py

Loads all CyberSentinel ML models once at application startup and stores
them in a ModelRegistry object that lives in app.state.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

from core.config import settings


DEFAULT_PACKET_MODEL_TYPE = "random_forest"
PACKET_MODEL_TYPES = ("random_forest", "decision_tree", "svm")
DEFAULT_CLUSTERING_ALGORITHM = "kmeans"
CLUSTERING_ALGORITHMS = ("kmeans", "dbscan")


@dataclass
class ModelRegistry:
    """Holds references to every loaded ML model."""

    packet_classifiers: dict[str, object] = field(default_factory=dict, repr=False)
    packet_classifier: object | None = field(default=None, repr=False)
    firewall_pipelines: dict[str, object] = field(default_factory=dict, repr=False)
    firewall_pipeline: object | None = field(default=None, repr=False)

    packet_classifier_available: bool = False
    firewall_pipeline_available: bool = False

    packet_classifier_meta: dict = field(default_factory=dict)
    firewall_pipeline_meta: dict = field(default_factory=dict)

    @classmethod
    async def load(cls) -> "ModelRegistry":
        registry = cls()
        await registry._load_packet_classifiers()
        await registry._load_firewall_pipelines()
        registry._log_summary()
        return registry

    async def _load_packet_classifiers(self) -> None:
        model_dir = settings.SUPERVISED_MODEL_DIR
        legacy_files = [
            model_dir / "packet_classifier.pkl",
            model_dir / "packet_scaler.pkl",
            model_dir / "packet_label_encoder.pkl",
            model_dir / "packet_features.pkl",
        ]
        typed_exists = any(
            settings.supervised_bundle_path_for(model_type).exists()
            for model_type in PACKET_MODEL_TYPES
        )
        legacy_bundle = settings.supervised_bundle_path
        if not typed_exists and not legacy_bundle.exists() and not all(path.exists() for path in legacy_files):
            logger.warning(
                "Supervised model files not found in {path}. "
                "Run supervised_learning/model.py to train them first.",
                path=model_dir,
            )
            return

        try:
            _add_to_sys_path(settings.SUPERVISED_MODEL_DIR.parent.parent)
            from supervised_learning.model import CyberSentinelPacketClassifier

            for model_type in PACKET_MODEL_TYPES:
                bundle_path = settings.supervised_bundle_path_for(model_type)
                if not bundle_path.exists() and not (
                    model_type == DEFAULT_PACKET_MODEL_TYPE and legacy_bundle.exists()
                ):
                    continue
                logger.info("Loading supervised packet classifier ({type})...", type=model_type)
                classifier = CyberSentinelPacketClassifier.load_model(model_dir, model_type=model_type)
                self.packet_classifiers[model_type] = classifier

            if not self.packet_classifiers:
                raise FileNotFoundError("No supervised classifier bundles could be loaded.")

            self.packet_classifier = self.packet_classifiers.get(
                DEFAULT_PACKET_MODEL_TYPE,
                next(iter(self.packet_classifiers.values())),
            )
            self.packet_classifier_available = True
            self.packet_classifier_meta = {
                "available_model_types": sorted(self.packet_classifiers.keys()),
                "default_model_type": DEFAULT_PACKET_MODEL_TYPE,
            }
            default_report = getattr(self.packet_classifier, "training_report", None)
            if default_report:
                self.packet_classifier_meta.update(
                    {
                        "accuracy": getattr(default_report, "accuracy", None),
                        "f1_weighted": getattr(default_report, "f1_weighted", None),
                        "classes": getattr(default_report, "classes", []),
                    }
                )
            logger.success(
                "Supervised packet classifiers loaded: {types}",
                types=", ".join(sorted(self.packet_classifiers.keys())),
            )
        except Exception as exc:
            logger.error("Failed to load supervised packet classifiers: {error}", error=exc)
            self.packet_classifiers = {}
            self.packet_classifier = None
            self.packet_classifier_available = False

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
        _status(self.packet_classifier_available, "Supervised packet classifier")
        _status(self.firewall_pipeline_available, "Unsupervised firewall pipeline")
        logger.info("=" * 55)

    async def reload(self) -> None:
        logger.info("Reloading all ML models from disk...")
        self.packet_classifiers = {}
        self.packet_classifier = None
        self.packet_classifier_available = False
        self.firewall_pipelines = {}
        self.firewall_pipeline = None
        self.firewall_pipeline_available = False
        await self._load_packet_classifiers()
        await self._load_firewall_pipelines()
        self._log_summary()

    def require_packet_classifier(self, model_type: str | None = None) -> object:
        requested = model_type or DEFAULT_PACKET_MODEL_TYPE
        if requested in self.packet_classifiers:
            return self.packet_classifiers[requested]
        if DEFAULT_PACKET_MODEL_TYPE in self.packet_classifiers:
            return self.packet_classifiers[DEFAULT_PACKET_MODEL_TYPE]
        if self.packet_classifiers:
            return next(iter(self.packet_classifiers.values()))
        raise ModelNotAvailableError(
            "Supervised packet classifier is not loaded. "
            "Train the model first by running supervised_learning/model.py "
            "then restart the server."
        )

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
