import json
import os
import requests

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


def generate_secure_fix(code: str, finding: dict) -> dict:
    """Generate a safe, reviewable fixed version of one Python file using Groq."""
    api_key = (os.getenv("GROQ_API_KEY") or "").strip()
    if not api_key:
        return {
            "available": False,
            "summary": "AI auto-fix is disabled because GROQ_API_KEY is not configured.",
            "fixed_code": code,
            "changes": [],
        }

    finding_text = json.dumps(finding, indent=2)
    prompt = f'''You are CodeGuard AI Auto-Fix, a secure software remediation assistant.

Fix ONLY the security finding described below in the supplied Python source.

STRICT RULES:
1. Return a complete replacement for the entire Python file.
2. Preserve the original behavior and public interfaces as much as possible.
3. Make the smallest safe change necessary to remediate the specified finding.
4. Do not introduce new dependencies unless absolutely necessary.
5. Do not remove security checks merely to silence the finding.
6. Never expose, repeat, or invent secrets, API keys, passwords, tokens, or private keys.
7. Do not execute the code.
8. If the finding cannot be safely fixed without more context, return the original code unchanged and explain why.
9. The fixed_code must be valid Python source code.
10. Return ONLY valid JSON. No Markdown fences.

TARGET FINDING:
{finding_text}

ORIGINAL PYTHON SOURCE:
```python
{code}
```

Return exactly this JSON shape:
{{
  "summary": "Short explanation of what was changed.",
  "fixed_code": "Complete replacement Python source as a JSON string",
  "changes": ["Change 1", "Change 2"],
  "confidence": "HIGH"
}}
'''

    model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a secure code remediation engine. Output only valid JSON and never reveal secrets."
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 7000,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=90)
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"].strip()

        if content.startswith("```"):
            lines = content.splitlines()
            if lines and lines[0].strip().startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            content = "\n".join(lines).strip()

        result = json.loads(content)
        fixed_code = result.get("fixed_code")
        if not isinstance(fixed_code, str) or not fixed_code.strip():
            raise ValueError("AI did not return replacement source code.")

        # Validate that the model returned syntactically valid Python before showing it as a fix.
        compile(fixed_code, "<codeguard-ai-fix>", "exec")

        changes = result.get("changes", [])
        if not isinstance(changes, list):
            changes = []

        return {
            "available": True,
            "summary": result.get("summary", "A secure replacement was generated."),
            "fixed_code": fixed_code,
            "changes": [str(item) for item in changes],
            "confidence": result.get("confidence", "MEDIUM"),
        }

    except json.JSONDecodeError:
        return {"available": False, "summary": "AI returned an invalid JSON response.", "fixed_code": code, "changes": []}
    except SyntaxError as error:
        return {"available": False, "summary": f"AI generated code that failed Python syntax validation: {error}", "fixed_code": code, "changes": []}
    except requests.exceptions.HTTPError as error:
        try:
            error_data = response.json()
            error_message = error_data.get("error", {}).get("message", str(error))
        except Exception:
            error_message = str(error)
        return {"available": False, "summary": f"AI provider rejected the auto-fix request: {error_message}", "fixed_code": code, "changes": []}
    except requests.exceptions.Timeout:
        return {"available": False, "summary": "AI auto-fix timed out.", "fixed_code": code, "changes": []}
    except requests.exceptions.RequestException as error:
        return {"available": False, "summary": f"AI auto-fix request failed: {error}", "fixed_code": code, "changes": []}
    except Exception as error:
        return {"available": False, "summary": f"AI auto-fix failed: {error}", "fixed_code": code, "changes": []}
