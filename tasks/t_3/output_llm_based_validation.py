"""
Task 3A: Output Validation Guardrail

Prevent PII (Personally Identifiable Information) leaks even if the LLM
tries to share sensitive data. This is the last line of defense.

We demonstrate both approaches:
1. BLOCKING: Reject any response containing PII
2. REDACTION: Allow response but hide the PII
"""

from typing import Any, cast

from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage
from langchain_openai import ChatOpenAI, AzureChatOpenAI
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from pydantic import BaseModel, Field, SecretStr

from tasks._constants import DIAL_URL, DIAL_API_KEY


# ============================================================================
# DATA MODEL FOR VALIDATION RESULTS
# ============================================================================

class PiiEntity(BaseModel):
    """Information about a detected PII entity."""
    
    entity_type: str = Field(description="Type of PII (e.g., 'CREDIT_CARD', 'PHONE_NUMBER', 'EMAIL_ADDRESS')")
    value: str = Field(description="The actual sensitive value detected")
    start_index: int = Field(description="Character position where PII starts")
    end_index: int = Field(description="Character position where PII ends")


class OutputValidationResult(BaseModel):
    """Result of validating LLM output for PII."""
    
    contains_pii: bool = Field(description="True if any PII was detected")
    pii_entities: list[PiiEntity] = Field(description="List of detected PII entities")
    risk_level: str = Field(description="'LOW', 'MEDIUM', or 'HIGH' based on PII severity")
    original_text: str = Field(description="The original response text")
    redacted_text: str = Field(description="The text with PII redacted")


# ============================================================================
# PII DETECTION AND REDACTION SYSTEM
# ============================================================================

class OutputValidationGuardrail:
    """
    Analyzes LLM output for PII and prevents it from being shared.
    
    The guardrail:
    1. Detects PII using pattern recognition
    2. Classifies the risk level
    3. Either blocks the response or redacts sensitive data
    """
    
    # Map of entity types to their sensitivity levels
    ENTITY_RISK_LEVELS = {
        'CREDIT_CARD': 'HIGH',
        'PHONE_NUMBER': 'HIGH',
        'EMAIL_ADDRESS': 'MEDIUM',
        'PERSON': 'MEDIUM',
        'DATE_TIME': 'LOW',
        'IBAN': 'HIGH',
        'SSN': 'HIGH',
        'US_SSN': 'HIGH',
        'IP_ADDRESS': 'MEDIUM',
    }
    
    def __init__(self, mode: str = "redact"):
        """
        Initialize the output validation guardrail.
        
        Args:
            mode: 'block' to reject responses with PII, or 'redact' to hide PII
        """
        self.mode = mode
        
        # Initialize Presidio tools for PII detection and redaction
        # Presidio is an open-source library for detecting and removing PII
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
    
    def validate_output(self, llm_response: str) -> OutputValidationResult:
        """
        Analyze LLM output for PII and prepare redacted version.
        
        Args:
            llm_response: The text response from the LLM
        
        Returns:
            OutputValidationResult with detected PII and redacted text
        """
        
        # Analyze the response for PII
        # This returns a list of detected entities like credit cards, phone numbers, etc.
        pii_results = self.analyzer.analyze(text=llm_response, language="en")
        
        # Convert Presidio results to our PiiEntity format
        pii_entities = []
        max_risk_level = 'LOW'
        
        for result in pii_results:
            # Extract entity information
            entity = PiiEntity(
                entity_type=result.entity_type,
                value=llm_response[result.start:result.end],
                start_index=result.start,
                end_index=result.end,
            )
            pii_entities.append(entity)
            
            # Track the highest risk level found
            entity_risk = self.ENTITY_RISK_LEVELS.get(result.entity_type, 'LOW')
            if entity_risk == 'HIGH' or max_risk_level == 'LOW':
                max_risk_level = entity_risk
        
        # Create redacted version of the response using Presidio
        # This replaces PII with placeholders like <CREDIT_CARD>, <PHONE_NUMBER>, etc.
        redacted_response = self.anonymizer.anonymize(
            text=llm_response,
            analyzer_results=cast(list[Any], pii_results),
        )
        
        # Create and return the validation result
        return OutputValidationResult(
            contains_pii=len(pii_entities) > 0,
            pii_entities=pii_entities,
            risk_level=max_risk_level,
            original_text=llm_response,
            redacted_text=redacted_response.text,
        )
    
    def process_response(self, llm_response: str, verbose: bool = False) -> tuple[bool, str]:
        """
        Process LLM response according to the configured mode.
        
        Args:
            llm_response: The text response from the LLM
            verbose: Print detailed analysis
        
        Returns:
            A tuple of:
            - allowed: bool - whether the response can be shown or should be blocked
            - output: str - the safe version of the response (redacted or error message)
        """
        
        # Validate the output
        result = self.validate_output(llm_response)
        
        if verbose:
            print("PII Detection Results:")
            print(f"  Contains PII: {result.contains_pii}")
            print(f"  Risk Level: {result.risk_level}")
            print(f"  Entities Found: {len(result.pii_entities)}")
            for entity in result.pii_entities:
                print(f"    - {entity.entity_type}: '{entity.value}'")
            print()
        
        # Handle based on configured mode
        if not result.contains_pii:
            # No PII detected, response is safe
            return True, result.original_text
        
        elif self.mode == "redact":
            # Redact PII and return the modified response
            return True, result.redacted_text
        
        else:  # mode == "block"
            # Block the response completely
            message = (
                f"⚠️  Output contained sensitive information (Risk: {result.risk_level})\n"
                f"Detected PII types: {', '.join(set(e.entity_type for e in result.pii_entities))}\n\n"
                f"This response cannot be displayed for security reasons.\n"
                f"Please try a different question."
            )
            return False, message


# ============================================================================
# HELPER TO GET LLM RESPONSE
# ============================================================================

def get_llm_response(user_input: str) -> str:
    """
    Get a response from the LLM without any guardrails.
    (Used for demonstration purposes)
    
    Args:
        user_input: The user's query
    
    Returns:
        The LLM's response
    """
    
    system_prompt = """You are a helpful customer service agent with access to customer information.
    Answer questions about customers' personal details when asked.
    Be informative and complete in your responses."""

    llm = AzureChatOpenAI(
        temperature=0.5, # Slightly higher temp for more varied responses
        azure_deployment="gpt-4o",
        azure_endpoint=DIAL_URL,
        api_key=SecretStr(DIAL_API_KEY),
        api_version="2024-02-15-preview",
    )
    
    messages: list[BaseMessage] = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_input),
    ]
    
    response = llm.invoke(messages)
    content = response.content
    return content if isinstance(content, str) else str(content)


# ============================================================================
# DEMONSTRATION
# ============================================================================

def demonstrate_output_validation() -> None:
    """Show how the output validation guardrail works with real LLM responses."""
    
    FETCHING_RESPONSE_MSG = "Getting LLM response..."
    
    print("=" * 80)
    print("OUTPUT VALIDATION GUARDRAIL DEMONSTRATION")
    print("=" * 80)
    print("\nThis demonstration shows the guardrail protecting against PII leaks")
    print("in actual LLM responses (not just hardcoded test strings).\n")
    
    # Example 1: Redaction Mode with Real LLM Response
    print("─" * 80)
    print("MODE 1: REDACTION (Hide sensitive data but show the response)")
    print("─" * 80)
    
    guardrail_redact = OutputValidationGuardrail(mode="redact")
    
    # Ask the LLM a question designed to elicit PII in the response
    user_query_1 = "Give me an example customer profile with name, phone, and email."
    print(f"User Query: {user_query_1}\n")
    print(FETCHING_RESPONSE_MSG)
    
    llm_response_1 = get_llm_response(user_query_1)
    print(f"\nOriginal LLM Response:\n{llm_response_1}\n")
    
    # Apply the guardrail
    allowed, output = guardrail_redact.process_response(llm_response_1, verbose=True)
    print(f"Redacted Output (safe to show user):\n{output}\n")
    
    # Example 2: Blocking Mode with Real LLM Response
    print("─" * 80)
    print("MODE 2: BLOCKING (Reject any response with PII)")
    print("─" * 80)
    
    guardrail_block = OutputValidationGuardrail(mode="block")
    
    # Ask for customer contact details - likely to contain PII
    user_query_2 = "Show me a sample customer record with contact information and credit card."
    print(f"User Query: {user_query_2}\n")
    print(FETCHING_RESPONSE_MSG)
    
    llm_response_2 = get_llm_response(user_query_2)
    print(f"\nLLM Response (contains PII):\n{llm_response_2}\n")
    
    # Apply blocking guardrail
    allowed, output = guardrail_block.process_response(llm_response_2, verbose=True)
    
    if allowed:
        print(f"✓ Output Allowed:\n{output}")
    else:
        print(f"✗ Output Blocked:\n{output}")
    
    # Example 3: Safe query (unlikely to contain PII)
    print("\n" + "─" * 80)
    print("EXAMPLE 3: Safe Response (No PII Expected)")
    print("─" * 80)
    
    user_query_3 = "What are your business hours and return policy?"
    print(f"User Query: {user_query_3}\n")
    print(FETCHING_RESPONSE_MSG)
    
    llm_response_3 = get_llm_response(user_query_3)
    print(f"\nLLM Response:\n{llm_response_3}\n")
    
    allowed, output = guardrail_redact.process_response(llm_response_3, verbose=True)
    print(f"Result: {'✓ Safe' if allowed else '✗ Blocked'}")
    print(f"Output:\n{output}")


# ============================================================================
# INTEGRATION EXAMPLE
# ============================================================================

def example_integration_with_input_validation() -> None:
    """
    Example showing how to combine input and output validation.
    
    This demonstrates the full protection flow:
    1. Input validation (Task 2) - Check user request
    2. Main LLM processing
    3. Output validation (Task 3A) - Check response
    """
    
    print("\n" + "=" * 80)
    print("FULL FLOW: INPUT + OUTPUT VALIDATION")
    print("=" * 80)
    
    # This example shows the ideal architecture
    architecture = """
    User Input
         ↓
    ┌────────────────────────────────────┐
    │  INPUT VALIDATION (Task 2)         │  ← Blocks malicious requests
    │  - Check for injection attacks     │
    │  - Block suspicious inputs         │
    └────────────────────────────────────┘
         ↓ (if passed)
    ┌────────────────────────────────────┐
    │  MAIN LLM PROCESSING               │  ← Hardened system prompt (Task 1)
    │  - Answers user question           │
    │  - Uses hardened system prompt     │
    └────────────────────────────────────┘
         ↓
    ┌────────────────────────────────────┐
    │  OUTPUT VALIDATION (Task 3A)       │  ← Prevents PII leaks
    │  - Detect PII in response          │
    │  - Redact or block if needed       │
    └────────────────────────────────────┘
         ↓
    User Gets Safe Response
    
    This multi-layered approach is much more secure than relying on
    just the system prompt!
    """
    
    print(architecture)
    
    print("\n" + "─" * 80)
    print("KEY BENEFITS OF THIS ARCHITECTURE:")
    print("─" * 80)
    print("""
1. DEFENSE IN DEPTH
   - Multiple layers catch different attack vectors
   - Even if one layer fails, others protect you
   
2. SEPARATION OF CONCERNS
   - Input validation focuses on request analysis
   - Output validation focuses on response safety
   - System prompt focuses on instruction hardening
   
3. FLEXIBILITY
   - Can use different strategies for different use cases
   - Can adjust security levels independently
   - Can add more layers as needed
   
4. AUDITABILITY
   - Each layer can log what it catches
   - Easier to debug security issues
   - Better compliance documentation
""")


def main() -> None:
    """Run the demonstration and integration example."""
    demonstrate_output_validation()
    example_integration_with_input_validation()


if __name__ == "__main__":
    main()
