import os
import json
import requests

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


def review_code_with_ai(code: str, findings: list) -> dict:
    """Send Python code and static-analysis findings to Groq for AI review."""
    api_key = (os.getenv("GROQ_API_KEY") or "").strip()
    if not api_key:
        return {"available": False, "summary": "AI review is disabled because GROQ_API_KEY is not configured.", "overall_assessment": "Static analysis is available, but AI review requires a Groq API key.", "recommendations": [], "finding_explanations": []}

    findings_text = json.dumps(findings, indent=2)
    prompt = f'''You are CodeGuard AI, a professional software security and code-review assistant.

Review the Python source code below.

Your job:
1. Explain the existing security findings.
2. Identify important code-quality problems.
3. Explain why each issue matters.
4. Give practical fixes.
5. Keep explanations beginner-friendly.
6. Do not invent vulnerabilities.
7. Do not execute the code.
8. Never expose or repeat secrets, API keys, passwords, tokens, or private keys.

STATIC ANALYSIS FINDINGS:
{findings_text}

PYTHON SOURCE CODE:
```python
{code}
```

Return ONLY valid JSON using exactly this structure:

{{
    "summary": "Short overall summary of the code.",
    "overall_assessment": "Overall security and code-quality assessment.",
    "recommendations": [
        "Recommendation 1",
        "Recommendation 2",
        "Recommendation 3"
    ],
    "finding_explanations": [
        {{
            "severity": "CRITICAL",
            "category": "Security",
            "line": 1,
            "explanation": "Explain the problem without exposing secrets.",
            "fix": "Explain how to fix the problem."
        }}
    ]
}}
'''

    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are CodeGuard AI, a professional and secure Python code-review assistant. Never expose secrets."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2,
        "max_tokens": 3000
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        ai_content = data["choices"][0]["message"]["content"].strip()

        if ai_content.startswith("```"):
            lines = ai_content.splitlines()
            if lines and lines[0].strip().startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            ai_content = "\n".join(lines).strip()

        result = json.loads(ai_content)
        if not isinstance(result, dict):
            raise ValueError("AI returned an invalid JSON object.")

        recommendations = result.get("recommendations", [])
        finding_explanations = result.get("finding_explanations", [])
        if not isinstance(recommendations, list):
            recommendations = []
        if not isinstance(finding_explanations, list):
            finding_explanations = []

        return {
            "available": True,
            "summary": result.get("summary", "AI review completed."),
            "overall_assessment": result.get("overall_assessment", "No overall assessment was provided."),
            "recommendations": recommendations,
            "finding_explanations": finding_explanations
        }

    except json.JSONDecodeError:
        return {"available": False, "summary": "AI returned an invalid JSON response.", "overall_assessment": "The AI response could not be parsed.", "recommendations": [], "finding_explanations": []}
    except requests.exceptions.HTTPError as error:
        try:
            error_data = response.json()
            error_message = error_data.get("error", {}).get("message", str(error))
        except Exception:
            error_message = str(error)
        return {"available": False, "summary": "AI provider rejected the request.", "overall_assessment": error_message, "recommendations": [], "finding_explanations": []}
    except requests.exceptions.Timeout:
        return {"available": False, "summary": "AI review timed out.", "overall_assessment": "The AI provider took too long to respond.", "recommendations": [], "finding_explanations": []}
    except requests.exceptions.RequestException as error:
        return {"available": False, "summary": "AI review request failed.", "overall_assessment": str(error), "recommendations": [], "finding_explanations": []}
    except KeyError:
        return {"available": False, "summary": "AI provider returned an unexpected response.", "overall_assessment": "The expected AI response format was not found.", "recommendations": [], "finding_explanations": []}
    except Exception as error:
        return {"available": False, "summary": "AI review failed.", "overall_assessment": str(error), "recommendations": [], "finding_explanations": []}
