import json
import threading
import requests
from requests.exceptions import RequestException
import yaml

from utils.output import print, section
from utils.report import get_recon_state


def load_config():
    try:
        with open("config/settings.yaml", "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return {}


# preload the model so it's ready when we need it (we should make this earlier i think)
def preload_model_async(verbose: bool = False) -> None:
    """Preload the local Ollama model in the background."""

    config = load_config()
    model = config.get('ai', {}).get('model', 'phi3')

    def _preload():
        try:
            requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": model,
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
def analyze_recon(ai_enabled: bool = False) -> None:
    """Analyze recon data using local AI."""
    if not ai_enabled:
        return
    
    section("AI Analysis") 
        
    print("[WARNING] AI analysis is experimental and may be inaccurate. Always verify manually.")
    print()
    print("[AI] Thinking...", flush=True)


    data = get_recon_state() 

    prompt = build_ai_prompt(data)
    result = call_local_ai(prompt)

    if result:
        render_ai_output(result)


# prompt creation with strict rules (needs refining but good start)
def build_ai_prompt(data: dict) -> str:
    """Build compact prompt with strict completion rules."""

    config = load_config()
    ai_config = config.get('ai', {})
    prompt_template = ai_config.get('prompt', 
        "You are a penetration testing decision engine. Analyze the provided recon data and provide actionable next steps."
    )

    recon_json = json.dumps(data, separators=(",", ":"), sort_keys=True)

    return f"{prompt_template}\n{recon_json}"


# ai call with phi3/120s time/streaming/raw text
def call_local_ai(prompt: str):
    """Call Ollama safely and return raw text."""

    config = load_config()
    ai_config = config.get('ai', {})

    model = ai_config.get('model', 'phi3')
    num_predict = ai_config.get('num_predict', 120)
    temperature = ai_config.get('temperature', 0.2)

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": num_predict,
                    "temperature": temperature
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