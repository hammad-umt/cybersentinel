"""
models/loader.py

Loads all CyberSentinel ML models once at application startup and stores
them in a ModelRegistry object that lives in app.state.

Why a registry pattern?
  - Models are expensive to load (100ms–2s each). Loading per-request would
    make every endpoint slow and waste memory.
  - app.state survives the full lifetime of the FastAPI process.
  - Every service just does: request.app.state.models.packet_classifier

Usage in main.py lifespan:
    from models.loader import ModelRegistry
    app.state.models = await ModelRegistry.load()

Usage in a service:
    registry: ModelRegistry = request.app.state.models
    result = registry.packet_classifier.predict(df)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

from core.config import settings


# ---------------------------------------------------------------------------
# We import the ML classes lazily inside load() so that if a model file is
# missing the app still starts — it just marks that model as unavailable.
# ---------------------------------------------------------------------------


@dataclass
class ModelRegistry:
    """
    Holds references to every loaded ML model.
    Attributes are None if the model file was missing or failed to load.
    Check .packet_classifier_available and .firewall_pipeline_available
    before using them in services.
    """

    # Supervised — CyberSentinelPacketClassifier instance
    packet_classifier: object | None = field(default=None, repr=False)

    # Unsupervised — UnsupervisedPipeline instance
    firewall_pipeline: object | None = field(default=None, repr=False)

    # Load status — checked by health endpoint and services
    packet_classifier_available: bool = False
    firewall_pipeline_available: bool = False

    # Metadata shown on /health endpoint
    packet_classifier_meta: dict = field(default_factory=dict)
    firewall_pipeline_meta: dict = field(default_factory=dict)

    @classmethod
    async def load(cls) -> "ModelRegistry":
        """
        Loads all models from disk.
        Called once in main.py lifespan on startup.
        Never raises — logs errors and marks models as unavailable instead,
        so the app can still serve endpoints that don't need that model.
        """
        registry = cls()
        await registry._load_packet_classifier()
        await registry._load_firewall_pipeline()
        registry._log_summary()
        return registry

    # ------------------------------------------------------------------
    # Private loaders
    # ------------------------------------------------------------------

    async def _load_packet_classifier(self) -> None:
        """Load the supervised RandomForest packet classifier bundle."""
        bundle_path = settings.supervised_bundle_path

        legacy_files = [
            bundle_path.parent / "packet_classifier.pkl",
            bundle_path.parent / "packet_scaler.pkl",
            bundle_path.parent / "packet_label_encoder.pkl",
            bundle_path.parent / "packet_features.pkl",
        ]
        if not bundle_path.exists() and not all(path.exists() for path in legacy_files):
            logger.warning(
                "Supervised model files not found in {path}. "
                "Run supervised_learning/model.py to train it first. "
                "POST /api/v1/packet/classify will return 503 until the model is loaded.",
                path=bundle_path.parent,
            )
            return

        try:
            # Add supervised_learning to path so its internal imports resolve
            _add_to_sys_path(settings.SUPERVISED_MODEL_DIR.parent.parent)

            from supervised_learning.model import CyberSentinelPacketClassifier

            logger.info("Loading supervised packet classifier from {path}...", path=bundle_path)
            self.packet_classifier = CyberSentinelPacketClassifier.load_model(
                settings.SUPERVISED_MODEL_DIR
            )
            self.packet_classifier_available = True

            # Pull metadata from the training report if available
            report = getattr(self.packet_classifier, "training_report", None)
            if report:
                self.packet_classifier_meta = {
                    "accuracy": getattr(report, "accuracy", None),
                    "f1_weighted": getattr(report, "f1_weighted", None),
                    "classes": getattr(report, "classes", []),
                }
            logger.success("Supervised packet classifier loaded successfully.")

        except Exception as exc:
            logger.error(
                "Failed to load supervised packet classifier: {error}", error=exc
            )
            self.packet_classifier = None
            self.packet_classifier_available = False

    async def _load_firewall_pipeline(self) -> None:
        """Load the unsupervised Isolation Forest + KMeans firewall pipeline."""
        anomaly_path = settings.anomaly_model_path
        clustering_path = settings.clustering_model_path

        missing = [p for p in [anomaly_path, clustering_path] if not p.exists()]
        if missing:
            logger.warning(
                "Unsupervised model files not found: {paths}. "
                "Run unsupervised_learning/train.py first. "
                "POST /api/v1/firewall/analyze will return 503 until models are loaded.",
                paths=[str(p) for p in missing],
            )
            return

        try:
            # Add unsupervised_learning to path so its internal imports resolve
            _add_to_sys_path(
                settings.UNSUPERVISED_MODEL_DIR.parent.parent / "unsupervised_learning"
            )

            from pipeline import UnsupervisedPipeline
            from config import PipelineConfig

            config = PipelineConfig(
                model_dir=str(settings.UNSUPERVISED_MODEL_DIR),
                anomaly_model_filename=anomaly_path.name,
                clustering_model_filename=clustering_path.name,
            )

            logger.info(
                "Loading unsupervised firewall pipeline from {dir}...",
                dir=settings.UNSUPERVISED_MODEL_DIR,
            )
            pipeline = UnsupervisedPipeline(config)
            pipeline.load_pipeline()

            self.firewall_pipeline = pipeline
            self.firewall_pipeline_available = True

            # Pull metadata from anomaly model
            anomaly_meta = getattr(pipeline.anomaly_model, "metadata", {})
            cluster_meta = getattr(pipeline.cluster_model, "metadata", {})
            self.firewall_pipeline_meta = {
                "anomaly_model": anomaly_meta,
                "clustering_model": cluster_meta,
            }
            logger.success("Unsupervised firewall pipeline loaded successfully.")

        except Exception as exc:
            logger.error(
                "Failed to load unsupervised firewall pipeline: {error}", error=exc
            )
            self.firewall_pipeline = None
            self.firewall_pipeline_available = False

    def _log_summary(self) -> None:
        """Log a clean startup summary of what loaded and what didn't."""
        logger.info("=" * 55)
        logger.info("CyberSentinel ML Model Registry — startup summary")
        logger.info("=" * 55)
        _status(self.packet_classifier_available, "Supervised packet classifier")
        _status(self.firewall_pipeline_available, "Unsupervised firewall pipeline")
        logger.info("=" * 55)

    # ------------------------------------------------------------------
    # Runtime reload — called by POST /api/v1/admin/reload-models
    # Useful after retraining without restarting the server.
    # ------------------------------------------------------------------

    async def reload(self) -> None:
        """Reload all models from disk without restarting the server."""
        logger.info("Reloading all ML models from disk...")
        self.packet_classifier = None
        self.packet_classifier_available = False
        self.firewall_pipeline = None
        self.firewall_pipeline_available = False
        await self._load_packet_classifier()
        await self._load_firewall_pipeline()
        self._log_summary()

    # ------------------------------------------------------------------
    # Guard helpers — used by services to fail fast with a clear message
    # ------------------------------------------------------------------

    def require_packet_classifier(self) -> object:
        """
        Returns the packet classifier or raises RuntimeError.
        Services call this instead of checking the flag themselves.
        """
        if not self.packet_classifier_available or self.packet_classifier is None:
            raise ModelNotAvailableError(
                "Supervised packet classifier is not loaded. "
                "Train the model first by running supervised_learning/model.py "
                "then restart the server."
            )
        return self.packet_classifier

    def require_firewall_pipeline(self) -> object:
        """Returns the firewall pipeline or raises RuntimeError."""
        if not self.firewall_pipeline_available or self.firewall_pipeline is None:
            raise ModelNotAvailableError(
                "Unsupervised firewall pipeline is not loaded. "
                "Train the model first by running unsupervised_learning/train.py "
                "then restart the server."
            )
        return self.firewall_pipeline


# ---------------------------------------------------------------------------
# Custom exception — caught by routers and converted to HTTP 503
# ---------------------------------------------------------------------------

class ModelNotAvailableError(RuntimeError):
    """Raised when a required ML model has not been loaded."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_to_sys_path(path: Path) -> None:
    """Add a directory to sys.path if it isn't already there."""
    str_path = str(path.resolve())
    if str_path not in sys.path:
        sys.path.insert(0, str_path)


def _status(available: bool, name: str) -> None:
    if available:
        logger.success("  ✓  {name}", name=name)
    else:
        logger.warning("  ✗  {name}  — NOT LOADED", name=name)
