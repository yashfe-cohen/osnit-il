import unittest
from unittest.mock import patch, MagicMock

from osnit.ner_engine import (
    is_ner_available,
    _split_into_chunks,
    extract_entities_ner,
    DEFAULT_NER_THRESHOLD
)
from osnit.extract import Extractor


class TestNEREngine(unittest.TestCase):
    def test_availability_check(self):
        avail = is_ner_available()
        self.assertIsInstance(avail, bool)

    def test_split_into_chunks(self):
        text = "משפט ראשון קצר. משפט שני קצת יותר ארוך.\nשורה חדשה לגמרי."
        chunks = _split_into_chunks(text, max_chars=30)
        self.assertTrue(len(chunks) >= 2)
        # Check offsets
        for chunk_text, offset in chunks:
            self.assertEqual(text[offset:offset + len(chunk_text)], chunk_text)

    def test_ner_fallback_when_disabled(self):
        with patch("osnit.ner_engine.is_ner_available", return_value=False):
            res = extract_entities_ner("ישראל ישראלי עובד במשרד הבריאות")
            self.assertEqual(res, [])

    def test_threshold_filtering_and_mapping(self):
        # Mock HF pipeline output with entities above and below 0.85
        mock_pipe = MagicMock()
        mock_pipe.return_value = [
            [
                {"entity_group": "PER", "word": "רועי ברק", "score": 0.94, "start": 0, "end": 8},
                {"entity_group": "PER", "word": "שם בספק", "score": 0.65, "start": 10, "end": 17},
                {"entity_group": "ORG", "word": "רפאל מערכות", "score": 0.91, "start": 20, "end": 31},
                {"entity_group": "LOC", "word": "תל אביב", "score": 0.88, "start": 35, "end": 42},
            ]
        ]

        with patch("osnit.ner_engine.is_ner_available", return_value=True), \
             patch("osnit.ner_engine.get_ner_pipeline", return_value=mock_pipe):
            entities = extract_entities_ner("רועי ברק ... רפאל מערכות ... תל אביב", threshold=0.85)
            
            # The entity with 0.65 score should be filtered out
            values = [e["value"] for e in entities]
            self.assertIn("רועי ברק", values)
            self.assertIn("רפאל מערכות", values)
            self.assertIn("תל אביב", values)
            self.assertNotIn("שם בספק", values)

            # Types mapped
            types = {e["value"]: e["type"] for e in entities}
            self.assertEqual(types["רועי ברק"], "person")
            self.assertEqual(types["רפאל מערכות"], "org")
            self.assertEqual(types["תל אביב"], "address")

    def test_integration_with_extractor(self):
        # When NER is available, Extractor.extract picks up entities without traditional titles
        fake_ner_output = [
            {"type": "person", "value": "איתמר בן שחר", "confidence": 0.92, "start": 10, "end": 22},
            {"type": "org", "value": "חברת סטרטאפ", "confidence": 0.89, "start": 30, "end": 41}
        ]

        text = "בפגישה שנערכה אתמול השתתף איתמר בן שחר מטעם חברת סטרטאפ בירושלים."
        with patch("osnit.ner_engine.is_ner_available", return_value=True), \
             patch("osnit.ner_engine.extract_entities_ner", return_value=fake_ner_output):
            ex = Extractor([]).extract(text)
            person_keys = [k for (t, k) in ex.ents if t == "person"]
            self.assertTrue(len(person_keys) > 0)
            self.assertTrue(any("איתמר" in k for k in person_keys))
