import requests
import json

# --- Configuration ---
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL_NAME = "llama3.1:8b"

# --- The Prompt Template ---
# Using {placeholders} for dynamic injection
PROMPT_TEMPLATE = (
    "You are a tool calling assistant you will recieve a user request, a tool call and a tool response. "
    "and your task is to answer the user request using the tool call and tool response.\n"
    "USER REQUEST: {user_request}\n"
    "TOOL CALL: {tool_call}\n"
    "TOOL RESPONSE: {tool_response}. "
    "You need to pay extra attention to the user request and the tool response. "
    "Your output format should be a json object (python dict). "
    "answer the user request, give the user bottom line conclusion."
)

def query_ollama_tool(user_request, tool_call, tool_response):
    """
    Constructs the prompt using the 3 variables, sends it to Ollama,
    and returns the JSON response.
    """
    
    # 1. Format the template with the provided arguments
    full_prompt = PROMPT_TEMPLATE.format(
        user_request=user_request,
        tool_call=tool_call,
        tool_response=tool_response
    )

    # 2. Prepare the payload
    # Note: "format": "json" enforces structured output
    payload = {
        "model": MODEL_NAME,
        "prompt": full_prompt,
        "stream": False,
        "format": "json" 
    }
    
    try:
        # 3. Send POST request to Ollama
        print(f"Sending request to {OLLAMA_URL}...")
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status() # Check for HTTP errors
        
        # 4. Extract and return the response text
        result = response.json()
        return result.get('response', '')

    except requests.exceptions.ConnectionError:
        print("[Error] Could not connect to Ollama. Is the Docker container running?")
        return None
    except Exception as e:
        print(f"[Error] An error occurred: {e}")
        return None

# --- Main Execution (Manual Testing) ---
if __name__ == "__main__":
    
    # Define your manual test variables here:
    my_user_request = "Can you retrieve details for the attack tactic TA0001? I want to understand what this tactic represents and how attackers typically use it."
    
    my_tool_call = "{'arguments': {'ID': 'TA0001'}, 'name': 'Get_an_attack_tactic_object'}"
    
    my_tool_response = """{
  "result": {
    "data": {
      "data": {
        "id": "TA0001",
        "type": "attack_tactic",
        "links": {
          "self": "https://www.virustotal.com/api/v3/attack_tactics/TA0001"
        },
        "attributes": {
          "creation_date": 1539735260,
          "link": "https://attack.mitre.org/tactics/TA0001/",
          "description": "The adversary is trying to get into your network.\n\nInitial Access consists of techniques that use various entry vectors to gain their initial foothold within a network. Techniques used to gain a foothold include targeted spearphishing and exploiting weaknesses on public-facing web servers. Footholds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.",
          "name": "Initial Access",
          "last_modification_date": 1745592336,
          "stix_id": "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca"
        }
      }"""

    # Call the function
    ai_answer = query_ollama_tool(
        user_request=my_user_request,
        tool_call=my_tool_call,
        tool_response=my_tool_response
    )

    # Print the result
    print("\n--- Model Response (JSON) ---")
    print(ai_answer)