from openai import OpenAI

client = OpenAI(
    api_key="sk-YgM-SrMIkmWgpC5dQQWX-w",
    base_url="https://elmodels.ngrok.app/v1",
)

response = client.chat.completions.create(
    model="nuha-2.0",
    messages=[
        {"role": "user", "content": "قل مرحبا"}
    ]
)

print(response.choices[0].message.content)