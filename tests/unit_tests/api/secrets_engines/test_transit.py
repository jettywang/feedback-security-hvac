#!/usr/bin/env python
"""Offline regression tests for Transit rewrap single and batch entry points.

These tests use fake ciphertexts only. They pin the original inputs and verify:
  * the exact JSON hvac sends to Vault,
  * that per-record derivation contexts survive both entry points,
  * that callers can tell, per batch item, which ciphertext may be replaced
    and which must keep its old ciphertext when successes and errors mix.
"""
import base64
import logging
from unittest import TestCase

import requests_mock

from hvac.adapters import JSONAdapter
from hvac.api.secrets_engines import Transit
from hvac.api.secrets_engines.transit import DEFAULT_MOUNT_POINT

KEY_NAME = "records-derived-key"
MOUNT_POINT = DEFAULT_MOUNT_POINT
MOCK_URL = "http://localhost:8200/v1/{mount_point}/rewrap/{name}".format(
    mount_point=MOUNT_POINT,
    name=KEY_NAME,
)


def _b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


# Contexts are derived from each record's purpose, as in production usage.
CONTEXT_PAYMENT = _b64("purpose:payment")
CONTEXT_EMAIL = _b64("purpose:email")
CONTEXT_AUDIT = _b64("purpose:audit")

# Fixed original inputs: ciphertexts from key versions v1/v2, fake payloads.
BATCH_INPUT = [
    {
        "ciphertext": "vault:v1:fake-payment-ciphertext",
        "context": CONTEXT_PAYMENT,
        "key_version": 1,
        "reference": "rec-payment",
    },
    {
        "ciphertext": "vault:v1:fake-email-ciphertext",
        "context": CONTEXT_EMAIL,
        "key_version": 2,
        "reference": "rec-email",
    },
    {
        # Empty context must be sent verbatim, not dropped.
        "ciphertext": "vault:v2:fake-audit-ciphertext",
        "context": "",
        "key_version": 2,
        "reference": "rec-audit",
    },
    {
        # Duplicate ciphertext and duplicate reference: only the batch index
        # can identify this item.
        "ciphertext": "vault:v1:fake-payment-ciphertext",
        "context": CONTEXT_PAYMENT,
        "key_version": 1,
        "reference": "rec-payment",
    },
]


def _partition_batch_results(batch_input, batch_results):
    """Caller-side view: which entries get a new ciphertext, which keep the old one."""
    replaceable = {}
    retained = {}
    for index, (item, result) in enumerate(zip(batch_input, batch_results)):
        if "error" in result:
            retained[index] = {
                "old_ciphertext": item["ciphertext"],
                "error": result["error"],
            }
        else:
            replaceable[index] = result["ciphertext"]
    return replaceable, retained


class TestTransitRewrap(TestCase):
    def setUp(self):
        self.transit = Transit(adapter=JSONAdapter())

    def test_single_entry_preserves_context_and_key_version(self):
        mock_response = {
            "data": {
                "ciphertext": "vault:v2:fake-rewrapped-payment",
                "key_version": 2,
            }
        }
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method="POST",
                url=MOCK_URL,
                status_code=200,
                json=mock_response,
            )
            rewrap_response = self.transit.rewrap_data(
                name=KEY_NAME,
                ciphertext="vault:v1:fake-payment-ciphertext",
                context=CONTEXT_PAYMENT,
                key_version=2,
                mount_point=MOUNT_POINT,
            )
            sent_json = requests_mocker.last_request.json()

        logging.debug("sent_json: %s" % sent_json)
        self.assertEqual(
            first={
                "ciphertext": "vault:v1:fake-payment-ciphertext",
                "context": CONTEXT_PAYMENT,
                "key_version": 2,
            },
            second=sent_json,
        )
        self.assertEqual(
            first=mock_response,
            second=rewrap_response,
        )
        self.assertEqual(
            first="vault:v2:fake-rewrapped-payment",
            second=rewrap_response["data"]["ciphertext"],
        )

    def test_single_entry_keeps_empty_context(self):
        mock_response = {
            "data": {
                "ciphertext": "vault:v2:fake-rewrapped-audit",
                "key_version": 2,
            }
        }
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method="POST",
                url=MOCK_URL,
                status_code=200,
                json=mock_response,
            )
            self.transit.rewrap_data(
                name=KEY_NAME,
                ciphertext="vault:v2:fake-audit-ciphertext",
                context="",
                mount_point=MOUNT_POINT,
            )
            sent_json = requests_mocker.last_request.json()

        logging.debug("sent_json: %s" % sent_json)
        self.assertEqual(
            first={
                "ciphertext": "vault:v2:fake-audit-ciphertext",
                "context": "",
            },
            second=sent_json,
        )

    def test_single_entry_requires_ciphertext_or_batch_input(self):
        with self.assertRaises(ValueError) as cm:
            self.transit.rewrap_data(
                name=KEY_NAME,
                mount_point=MOUNT_POINT,
            )
        self.assertIn(
            member="ciphertext must be specified unless batch_input is set",
            container=str(cm.exception),
        )

    def test_batch_entry_preserves_per_item_context(self):
        mock_response = {
            "data": {
                "batch_results": [
                    {
                        "ciphertext": "vault:v2:fake-rewrapped-payment",
                        "key_version": 2,
                        "reference": "rec-payment",
                    },
                    {
                        "ciphertext": "vault:v2:fake-rewrapped-email",
                        "key_version": 2,
                        "reference": "rec-email",
                    },
                    {
                        "ciphertext": "vault:v2:fake-rewrapped-audit",
                        "key_version": 2,
                        "reference": "rec-audit",
                    },
                    {
                        "ciphertext": "vault:v2:fake-rewrapped-payment-dup",
                        "key_version": 2,
                        "reference": "rec-payment",
                    },
                ]
            }
        }
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method="POST",
                url=MOCK_URL,
                status_code=200,
                json=mock_response,
            )
            rewrap_response = self.transit.rewrap_data(
                name=KEY_NAME,
                batch_input=BATCH_INPUT,
                mount_point=MOUNT_POINT,
            )
            sent_json = requests_mocker.last_request.json()

        logging.debug("sent_json: %s" % sent_json)
        # Batch-only requests must not carry a top-level ciphertext, and the
        # batch_input list must be forwarded verbatim (contexts, empty context,
        # per-item key versions, duplicate references included).
        self.assertEqual(
            first={"batch_input": BATCH_INPUT},
            second=sent_json,
        )
        self.assertNotIn(
            member="ciphertext",
            container=sent_json,
        )
        self.assertEqual(
            first=mock_response,
            second=rewrap_response,
        )
        # Results are index-aligned with the input, so every item is
        # identifiable even with duplicate ciphertexts and references.
        batch_results = rewrap_response["data"]["batch_results"]
        self.assertEqual(
            first=len(BATCH_INPUT),
            second=len(batch_results),
        )
        replaceable, retained = _partition_batch_results(BATCH_INPUT, batch_results)
        self.assertEqual(
            first={
                0: "vault:v2:fake-rewrapped-payment",
                1: "vault:v2:fake-rewrapped-email",
                2: "vault:v2:fake-rewrapped-audit",
                3: "vault:v2:fake-rewrapped-payment-dup",
            },
            second=replaceable,
        )
        self.assertEqual(
            first={},
            second=retained,
        )

    def test_batch_entry_partial_errors_identify_replaceable_ciphertexts(self):
        mock_response = {
            "data": {
                "batch_results": [
                    {
                        "ciphertext": "vault:v2:fake-rewrapped-payment",
                        "key_version": 2,
                        "reference": "rec-payment",
                    },
                    {
                        "error": "invalid ciphertext: unable to decrypt",
                        "reference": "rec-email",
                    },
                    {
                        "ciphertext": "vault:v2:fake-rewrapped-audit",
                        "key_version": 2,
                        "reference": "rec-audit",
                    },
                    {
                        "error": "key version 1 is not allowed (min decryption version is 2)",
                        "reference": "rec-payment",
                    },
                ]
            }
        }
        with requests_mock.mock() as requests_mocker:
            requests_mocker.register_uri(
                method="POST",
                url=MOCK_URL,
                status_code=200,
                json=mock_response,
            )
            rewrap_response = self.transit.rewrap_data(
                name=KEY_NAME,
                batch_input=BATCH_INPUT,
                mount_point=MOUNT_POINT,
            )
            sent_json = requests_mocker.last_request.json()

        logging.debug("sent_json: %s" % sent_json)
        self.assertEqual(
            first={"batch_input": BATCH_INPUT},
            second=sent_json,
        )

        batch_results = rewrap_response["data"]["batch_results"]
        replaceable, retained = _partition_batch_results(BATCH_INPUT, batch_results)

        # Only items 0 and 2 may have their ciphertext swapped in.
        self.assertEqual(
            first={
                0: "vault:v2:fake-rewrapped-payment",
                2: "vault:v2:fake-rewrapped-audit",
            },
            second=replaceable,
        )
        # Items 1 and 3 must keep their old ciphertext; the caller sees the
        # per-item failure reason. Note item 3 shares ciphertext and reference
        # with item 0, so index alignment is what tells them apart.
        self.assertEqual(
            first={
                1: {
                    "old_ciphertext": "vault:v1:fake-email-ciphertext",
                    "error": "invalid ciphertext: unable to decrypt",
                },
                3: {
                    "old_ciphertext": "vault:v1:fake-payment-ciphertext",
                    "error": "key version 1 is not allowed (min decryption version is 2)",
                },
            },
            second=retained,
        )
        self.assertIn(
            member="unable to decrypt",
            container=batch_results[1]["error"],
        )
        self.assertIn(
            member="min decryption version",
            container=batch_results[3]["error"],
        )
