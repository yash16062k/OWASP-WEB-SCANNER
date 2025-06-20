# scanner/ai_explainer.py

import os
import openai
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("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")
client = openai.OpenAI(api_key=api_key)

def explain_issue(issue_type: str) -> str:
    prompt = (
        f"Explain the following web security issue in simple, non-technical terms for a report.\n"
        f"Issue: {issue_type}\n"
        f"Include:\n"
        f"1. What it is\n"
        f"2. Why it's risky\n"
        f"3. How to fix or mitigate it\n"
        f"Keep the explanation concise and professional without any emojis or bullet points."
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[!] Error while explaining {issue_type}: {e}")
        return "[Explanation unavailable]"