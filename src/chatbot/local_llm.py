from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

# ──────────────────────────────────────────────────────────────
# Local AI Model Setup (TinyLlama)
# Loads a lightweight instruction-tuned model for offline inference
# ──────────────────────────────────────────────────────────────
MODEL_NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"

print("Loading local AI model...")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    torch_dtype=torch.float32,
    device_map="auto"
)

print("AI model loaded successfully.")


# ──────────────────────────────────────────────────────────────
# Local LLM Inference Function
# Generates concise cybersecurity responses using TinyLlama
# ──────────────────────────────────────────────────────────────
def ask_local_llm(prompt: str) -> str:
    """
    Generate a response from the local AI model.

    - Restricts responses to cybersecurity topics only
    - Limits output to 5 concise bullet points
    - Applies post-processing to enforce brevity and clarity
    """

    # System instruction to constrain model behaviour
    system_prompt = (
        "You are a cybersecurity assistant. "
        "Only answer cybersecurity questions. "
        "If not related, say: 'I'm sorry, I can only provide advice on cybersecurity topics.' "
        "Answer in MAXIMUM 5 short bullet points."
    )

    # Construct chat-style prompt
    full_prompt = f"""
<|system|>
{system_prompt}

<|user|>
{prompt}

<|assistant|>
"""

    # Tokenise input prompt
    inputs = tokenizer(full_prompt, return_tensors="pt")

    # Generate response from model
    outputs = model.generate(
        **inputs,
        max_new_tokens=120,
        temperature=0.2,
        do_sample=True,
        pad_token_id=tokenizer.eos_token_id,
        eos_token_id=tokenizer.eos_token_id
    )

    # Decode and extract assistant response
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    response = response.split("<|assistant|>")[-1].strip()

    # ──────────────────────────────────────────────────────────
    # Post-processing: enforce short, structured responses
    # ──────────────────────────────────────────────────────────

    # Split into non-empty lines
    lines = [l.strip() for l in response.split("\n") if l.strip()]

    # Keep only bullet points or numbered steps
    filtered = [
        l for l in lines
        if l.startswith(("-", "*", "1", "2", "3", "4", "5"))
    ]

    # Limit to max 5 points OR fallback to short paragraph
    if filtered:
        trimmed = "\n".join(filtered[:5])
    else:
        trimmed = " ".join(lines[:2])

    return trimmed
