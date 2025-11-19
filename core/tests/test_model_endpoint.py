from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse


class ModelGetScoreViewTests(TestCase):
    def test_post_rejects_missing_features_key(self):
        response = self.client.post(
            reverse("model_get_score"),
            data="{}",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("features", response.json()["error"])

    def test_post_rejects_non_string_entries(self):
        payload = {"features": ["   ", 42]}
        response = self.client.post(
            reverse("model_get_score"),
            data=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    @patch(
        "core.views.predict_urls",
        return_value=[{"url": "example.com", "label": 0, "probability_unsafe": 0.1, "risk_level": "low_risk"}],
    )
    def test_post_returns_predictions(self, mock_predict):
        payload = {"features": ["https://example.com"]}
        response = self.client.post(
            reverse("model_get_score"),
            data=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body["prediction"]), 1)
        mock_predict.assert_called_once_with(["https://example.com"])

    def test_get_requires_any_url(self):
        response = self.client.get(reverse("model_get_score"))
        self.assertEqual(response.status_code, 400)

    @patch(
        "core.views.predict_urls",
        return_value=[{"url": "example.com", "label": 0, "probability_unsafe": 0.1, "risk_level": "low_risk"}],
    )
    def test_get_with_query_params(self, mock_predict):
        endpoint = reverse("model_get_score") + "?url=https://example.com&url=http://demo.test"
        response = self.client.get(endpoint)
        self.assertEqual(response.status_code, 200)
        mock_predict.assert_called_once_with(["https://example.com", "http://demo.test"])

    @patch(
        "core.views.predict_urls",
        return_value=[{"url": "example.com", "label": 0, "probability_unsafe": 0.1, "risk_level": "low_risk"}],
    )
    def test_get_with_path_segment(self, mock_predict):
        endpoint = reverse("model_get_score_single", kwargs={"url_value": "www.example.com"})
        response = self.client.get(endpoint)
        self.assertEqual(response.status_code, 200)
        mock_predict.assert_called_once_with(["www.example.com"])
