import json
import os
import requests

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


def generate_security_tests(original_code: str, fixed_code: str, finding: dict) -> dict:
    """Generate reviewable Python regression/security tests for a CodeGuard finding."""
    api_key = (os.getenv("GROQ_API_KEY") or "").strip()
    if not api_key:
        return {
            "available": False,
            "summary": "AI test generation is disabled because GROQ_API_KEY is not configured.",
            "test_code": "",
            "tests": [],
        }

    finding_text = json.dumps(finding, indent=2)
    prompt = f'''You are CodeGuard AI Test Generator, a secure software testing assistant.

Generate focused Python security/regression tests for the vulnerability below.
The tests are for HUMAN REVIEW and MUST NOT execute the target application during generation.

STRICT RULES:
1. Return ONLY valid JSON. No Markdown fences.
2. Return a complete standalone pytest test file.
3. Prefer standard library plus pytest only.
4. Do not access the network, filesystem outside pytest temporary paths, subprocesses, shells, credentials, or real services.
5. Do not invent secrets or require external services.
6. Tests should demonstrate the vulnerable behavior when practical and assert the secure behavior expected after remediation.
7. If importing the target module is unsafe or would cause side effects, write isolated tests around the relevant function/contract or clearly mark a test as requiring adaptation.
8. Keep tests deterministic and focused on the specified finding.
9. Include no more than 6 tests.
10. The generated test file must be syntactically valid Python.

TARGET FINDING:
{finding_text}

ORIGINAL SOURCE:
```python
{original_code}
```

FIXED SOURCE:
```python
{fixed_code}
```

Return exactly:
{{
  "summary": "Short explanation of the generated regression/security tests.",
  "test_code": "Complete pytest source as a JSON string",
  "tests": [
    {{"name": "test_name", "purpose": "What this test verifies"}}
  ]
}}
'''

    model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You generate safe, deterministic pytest security regression tests. Output only valid JSON.",
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
        test_code = result.get("test_code")
        if not isinstance(test_code, str) or not test_code.strip():
            raise ValueError("AI did not return test source code.")

        compile(test_code, "<codeguard-ai-tests>", "exec")
        tests = result.get("tests", [])
        if not isinstance(tests, list):
            tests = []

        return {
            "available": True,
            "summary": result.get("summary", "Security regression tests were generated."),
            "test_code": test_code,
            "tests": tests[:6],
        }
    except json.JSONDecodeError:
        return {"available": False, "summary": "AI returned an invalid JSON response.", "test_code": "", "tests": []}
    except SyntaxError as error:
        return {"available": False, "summary": f"Generated tests failed Python syntax validation: {error}", "test_code": "", "tests": []}
    except requests.exceptions.HTTPError as error:
        try:
            error_data = response.json()
            error_message = error_data.get("error", {}).get("message", str(error))
        except Exception:
            error_message = str(error)
        return {"available": False, "summary": f"AI provider rejected test generation: {error_message}", "test_code": "", "tests": []}
    except requests.exceptions.Timeout:
        return {"available": False, "summary": "AI test generation timed out.", "test_code": "", "tests": []}
    except requests.exceptions.RequestException as error:
        return {"available": False, "summary": f"AI test generation request failed: {error}", "test_code": "", "tests": []}
    except Exception as error:
        return {"available": False, "summary": f"AI test generation failed: {error}", "test_code": "", "tests": []}
