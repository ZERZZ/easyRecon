import json
import threading
import requests
from requests.exceptions import RequestException
from utils.output import print


# preload the model so it's ready when we need it (we should make this earlier i think)
def preload_model_async(verbose: bool = False) -> None:
    """Preload the local Ollama model in the background."""

    def _preload():
        try:
            requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "phi3",
                    "prompt": "Ready.",
                    "stream": False
                },
                timeout=60
            )
            if verbose:
                print("[AI] Model ready")
        except Exception:
            pass  

    if verbose:
        print("[AI] Preloading model in background...")

    threading.Thread(target=_preload, daemon=True).start()


# main call
def analyze_recon(data: dict, ai_enabled: bool = False) -> None:
    """Analyze recon data using local AI."""
    if not ai_enabled:
        return

    prompt = build_ai_prompt(data)
    result = call_local_ai(prompt)

    if result:
        render_ai_output(result)


# prompt creation with strict rules (needs refining but good start)
def build_ai_prompt(data: dict) -> str:
    """Build compact prompt with strict completion rules."""

    recon_json = json.dumps(data, separators=(",", ":"), sort_keys=True)

    return (
        "You are a penetration testing decision engine.\n"
        "Only use the provided recon data.\n"
        "Do not explain concepts. Do not be generic.\n"
        "Do not include anything not supported by the data.\n\n"

        "OUTPUT FORMAT (STRICT):\n"
        "Return ONLY 3 steps.\n"
        "Each step must be actionable and based ONLY on detected services.\n\n"

        "FORMAT:\n"
        "1. ...\n"
        "2. ...\n"
        "3. ...\n\n"

        "RULES:\n"
        "- No scanning advice unless missing data requires it\n"
        "- No repetition\n"
        "- No filler text\n"
        "- Keep each line concise\n"
        "- Do NOT expand summarized or truncated arrays (e.g. '... and another 99 users')\n"
        "- Only use explicitly listed items from recon data\n\n"

        f"{recon_json}"
    )


# ai call with phi3/120s time/streaming/raw text
def call_local_ai(prompt: str):
    """Call Ollama safely and return raw text."""

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "phi3",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": 120,
                    "temperature": 0.2
                }
            },
            timeout=120
        )

        response.raise_for_status()

        data = response.json()
        return data.get("response", "").strip()

    except Exception as e:
        print(f"[AI ERROR] {e}")
        return None


# output rendering with strict formatting (reduces prompt length, improving analysis efficiency and consistency)
def render_ai_output(text: str) -> None:
    """Render ONLY 3 steps cleanly."""

    steps = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        # remove numbering etc
        line = line.lstrip("1234567890. -$")

        if line:
            steps.append(line)

    # enforce exactly 3 outputs
    while len(steps) < 3:
        steps.append("No further actionable step identified")

    steps = steps[:3]

    print(f"1. {steps[0]}")
    print()
    print(f"2. {steps[1]}")
    print()
    print(f"3. {steps[2]}")
    print()