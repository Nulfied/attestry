"""Talking to models, over nothing but the standard library.

Four backends, one interface. ``ollama`` and ``echo`` cost nothing to run, which
matters: the point of a nightly drift suite is that it is cheap enough to
actually leave running, and a tool that only works against a paid API will get
switched off the first time somebody looks at a bill.

Every response carries the model string the provider *served*, not the one that
was asked for. That single field catches the failure this subsystem exists for:
an alias like ``gpt-4o`` or ``llama3`` quietly repointing at a new build. When
the served name differs from the requested one, the runner flags it before any
output comparison happens, because at that point you already know why the
behaviour moved.

API keys are read from the environment and never written to a run file, a
report or the ledger.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Mapping, Optional

from ..util.errors import AttestryError

__all__ = ["Response", "Provider", "PROVIDERS", "get_provider", "ProviderError"]


class ProviderError(AttestryError):
    """The model could not be reached, or refused the request."""


class Response:
    """One model reply, plus the metadata worth keeping."""

    __slots__ = ("text", "model", "latency_ms", "meta")

    def __init__(
        self,
        text: str,
        model: str = "",
        latency_ms: int = 0,
        meta: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.text = text
        self.model = model
        self.latency_ms = latency_ms
        self.meta = dict(meta or {})

    def __repr__(self) -> str:
        return "Response(%d chars, model=%s, %dms)" % (
            len(self.text), self.model, self.latency_ms
        )


class Provider:
    """Base class. Subclasses implement :meth:`complete`."""

    name = "base"
    #: Whether using this provider costs money. Reported by ``attestry doctor``.
    metered = False

    def __init__(self, model: str, **options: Any) -> None:
        self.model = model
        self.options = options

    def complete(
        self,
        prompt: str,
        system: str = "",
        params: Optional[Mapping[str, Any]] = None,
    ) -> Response:
        raise NotImplementedError

    def describe(self) -> str:
        return "%s:%s%s" % (self.name, self.model, " (metered)" if self.metered else "")


def _post_json(
    url: str,
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
    timeout: float = 120.0,
    retries: int = 3,
) -> Dict[str, Any]:
    """POST JSON with backoff on the failures that are worth retrying.

    429 and 5xx are transient; 4xx otherwise means the request was wrong and
    retrying it just wastes time and quota. Error bodies are truncated before
    being raised, since providers sometimes echo the prompt back in them.
    """
    body = json.dumps(payload).encode("utf-8")
    last_error: Optional[str] = None
    for attempt in range(retries):
        request = urllib.request.Request(url, data=body, method="POST")
        for key, value in headers.items():
            request.add_header(key, value)
        request.add_header("content-type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as handle:
                return json.loads(handle.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            if exc.code in (408, 409, 429) or exc.code >= 500:
                last_error = "HTTP %s: %s" % (exc.code, detail)
                time.sleep(min(2 ** attempt, 8))
                continue
            raise ProviderError("HTTP %s from %s: %s" % (exc.code, url, detail))
        except urllib.error.URLError as exc:
            last_error = str(exc.reason)
            time.sleep(min(2 ** attempt, 8))
        except ValueError as exc:
            raise ProviderError("%s returned something that is not JSON: %s" % (url, exc))
    raise ProviderError("%s unreachable after %d attempts: %s" % (url, retries, last_error))


class EchoProvider(Provider):
    """A deterministic stand-in, so the tooling can be exercised for free.

    It is not a model and does not pretend to be one. It exists so that the test
    suite, the examples and a first run of ``attestry drift run`` all work on a
    machine with no API key and no network -- and so that drift detection itself
    can be tested, which requires a model whose behaviour you can change on
    purpose.

    Setting ``ATTESTRY_ECHO_VARIANT`` changes how it answers. That is the knob
    the shipped example uses to simulate a provider updating a model underneath
    you.
    """

    name = "echo"
    metered = False

    def complete(
        self,
        prompt: str,
        system: str = "",
        params: Optional[Mapping[str, Any]] = None,
    ) -> Response:
        variant = self.options.get("variant") or os.environ.get("ATTESTRY_ECHO_VARIANT", "a")
        words = prompt.strip().split()
        summary = " ".join(words[:12])
        if variant == "a":
            text = "Answer: %s. Confidence: high. Words: %d." % (summary, len(words))
        elif variant == "b":
            # Same facts, different presentation: the shape of real drift after
            # a provider retunes a model's style.
            text = (
                "I think the answer here is %s, though it depends on context. "
                "There were %d words." % (summary.lower(), len(words))
            )
        else:
            text = "Answer: %s." % summary
        served = "%s-variant-%s" % (self.model, variant)
        return Response(text=text, model=served, latency_ms=0, meta={"variant": variant})


class OllamaProvider(Provider):
    """Local models via Ollama. Free to run, which is the point."""

    name = "ollama"
    metered = False

    def complete(
        self,
        prompt: str,
        system: str = "",
        params: Optional[Mapping[str, Any]] = None,
    ) -> Response:
        params = dict(params or {})
        host = self.options.get("host") or os.environ.get(
            "OLLAMA_HOST", "http://localhost:11434"
        )
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        options: Dict[str, Any] = {}
        if "temperature" in params:
            options["temperature"] = params["temperature"]
        if "seed" in params:
            options["seed"] = params["seed"]
        if "max_tokens" in params:
            options["num_predict"] = params["max_tokens"]
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": options,
        }
        started = time.time()
        data = _post_json(host.rstrip("/") + "/api/chat", payload, {})
        text = (data.get("message") or {}).get("content", "")
        return Response(
            text=text,
            model=data.get("model", self.model),
            latency_ms=int((time.time() - started) * 1000),
            meta={"eval_count": data.get("eval_count")},
        )


class OpenAIProvider(Provider):
    """OpenAI Chat Completions."""

    name = "openai"
    metered = True

    def complete(
        self,
        prompt: str,
        system: str = "",
        params: Optional[Mapping[str, Any]] = None,
    ) -> Response:
        params = dict(params or {})
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ProviderError("OPENAI_API_KEY is not set")
        base = self.options.get("base_url") or os.environ.get(
            "OPENAI_BASE_URL", "https://api.openai.com/v1"
        )
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload: Dict[str, Any] = {"model": self.model, "messages": messages}
        for key_name in ("temperature", "top_p", "max_tokens", "seed"):
            if key_name in params:
                payload[key_name] = params[key_name]
        started = time.time()
        data = _post_json(
            base.rstrip("/") + "/chat/completions",
            payload,
            {"authorization": "Bearer %s" % key},
        )
        choices = data.get("choices") or [{}]
        text = ((choices[0].get("message") or {}).get("content")) or ""
        return Response(
            text=text,
            model=data.get("model", self.model),
            latency_ms=int((time.time() - started) * 1000),
            meta={
                # A changed fingerprint is the provider telling you the serving
                # stack moved, which is drift you can catch before the outputs do.
                "system_fingerprint": data.get("system_fingerprint"),
                "usage": data.get("usage"),
            },
        )


class AnthropicProvider(Provider):
    """Anthropic Messages API."""

    name = "anthropic"
    metered = True

    def complete(
        self,
        prompt: str,
        system: str = "",
        params: Optional[Mapping[str, Any]] = None,
    ) -> Response:
        params = dict(params or {})
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ProviderError("ANTHROPIC_API_KEY is not set")
        base = self.options.get("base_url") or os.environ.get(
            "ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1"
        )
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": params.get("max_tokens", 1024),
        }
        if system:
            payload["system"] = system
        for key_name in ("temperature", "top_p"):
            if key_name in params:
                payload[key_name] = params[key_name]
        started = time.time()
        data = _post_json(
            base.rstrip("/") + "/messages",
            payload,
            {
                "x-api-key": key,
                "anthropic-version": self.options.get("api_version", "2023-06-01"),
            },
        )
        blocks = data.get("content") or []
        text = "".join(
            block.get("text", "") for block in blocks if block.get("type") == "text"
        )
        return Response(
            text=text,
            model=data.get("model", self.model),
            latency_ms=int((time.time() - started) * 1000),
            meta={"usage": data.get("usage"), "stop_reason": data.get("stop_reason")},
        )


PROVIDERS = {
    "echo": EchoProvider,
    "ollama": OllamaProvider,
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
}


def get_provider(name: str, model: str, **options: Any) -> Provider:
    try:
        factory = PROVIDERS[name]
    except KeyError:
        raise ProviderError(
            "unknown provider %r; available: %s" % (name, ", ".join(sorted(PROVIDERS)))
        )
    return factory(model, **options)
