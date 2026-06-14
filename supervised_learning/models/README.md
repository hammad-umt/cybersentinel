# Supervised Model Artifacts

Training writes packet classifier artifacts here.

Expected files after training can include:

- `packet_classifier_pipeline.joblib`
- `packet_classifier.pkl`
- `packet_scaler.pkl`
- `packet_label_encoder.pkl`
- `packet_features.pkl`
- `packet_classifier_metrics.json`

Generated artifacts are ignored by Git by default. Use Git LFS or release assets if you need to publish trained models.
