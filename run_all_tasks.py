"""
Main Runner Script - Run All Guardrails Tasks

This script demonstrates all four guardrails tasks in sequence:
1. Task 1: Prompt Injection - Understanding injection attacks and defenses
2. Task 2: Input Validation - Blocking malicious requests
3. Task 3A: Output Validation - Preventing PII leaks
4. Task 3B: Streaming - Real-time PII filtering

Run with: python run_all_tasks.py
"""

import sys
from pathlib import Path

# Add the workspace to path so we can import tasks
workspace_root = Path(__file__).parent
sys.path.insert(0, str(workspace_root))

# Import task modules
from tasks.t_1 import prompt_injection
from tasks.t_2 import input_llm_based_validation
from tasks.t_3 import output_llm_based_validation
from tasks.t_3 import streaming_pii_guardrail


def print_header(title: str, size: int = 80) -> None:
    """Print a formatted header."""
    print("\n" + "=" * size)
    print(title.center(size))
    print("=" * size + "\n")


def run_task_1() -> None:
    """Run Task 1: Prompt Injection demonstration."""
    print_header("TASK 1: UNDERSTANDING PROMPT INJECTIONS")
    print("""
This task demonstrates:
✓ How prompt injection attacks work
✓ A vulnerable system prompt vs a hardened one
✓ Various attack techniques and defenses
✓ Key principles for secure prompt engineering
""")
    input("\nPress Enter to start Task 1 demonstration...")
    prompt_injection.demonstrate_prompt_injection()
    print("\n")
    prompt_injection.print_learning_summary()


def run_task_2() -> None:
    """Run Task 2: Input Validation demonstration."""
    print_header("TASK 2: INPUT VALIDATION GUARDRAIL")
    print("""
This task demonstrates:
✓ Detecting prompt injection attacks in user input
✓ Analyzing requests for suspicious patterns
✓ Blocking or allowing requests based on risk analysis
✓ Integration with the main system
""")
    input("\nPress Enter to start Task 2 demonstration...")
    input_llm_based_validation.demonstrate_input_validation()
    print("\n")
    input_llm_based_validation.print_usage_guide()


def run_task_3a() -> None:
    """Run Task 3A: Output Validation demonstration."""
    print_header("TASK 3A: OUTPUT VALIDATION GUARDRAIL")
    print("""
This task demonstrates:
✓ Detecting PII (Personally Identifiable Information) in responses
✓ Two modes: REDACTION and BLOCKING
✓ Understanding risk levels of different PII types
✓ Multi-layered security approach
""")
    input("\nPress Enter to start Task 3A demonstration...")
    output_llm_based_validation.demonstrate_output_validation()
    print("\n")
    output_llm_based_validation.example_integration_with_input_validation()


def run_task_3b() -> None:
    """Run Task 3B: Streaming PII Guardrail demonstration."""
    print_header("TASK 3B: STREAMING PII GUARDRAIL")
    print("""
This task demonstrates:
✓ Real-time filtering of streaming responses
✓ Pattern-based vs context-aware detection
✓ Performance vs accuracy trade-offs
✓ Practical implementation for web applications
""")
    input("\nPress Enter to start Task 3B demonstration...")
    streaming_pii_guardrail.example_streaming_simulation()
    print("\n")
    streaming_pii_guardrail.example_with_real_streaming()
    print_header("PERFORMANCE CONSIDERATIONS", size=80)
    streaming_pii_guardrail.print_performance_considerations()


def print_final_summary() -> None:
    """Print a comprehensive summary of all tasks."""
    summary = """
╔════════════════════════════════════════════════════════════════════════════╗
║                       COMPREHENSIVE GUARDRAILS ARCHITECTURE                ║
╚════════════════════════════════════════════════════════════════════════════╝

YOU'VE LEARNED ABOUT A COMPLETE SECURITY SYSTEM with 4 layers:

┌─────────────────────────────────────────────────────────────────────────┐
│ 1. HARDENED SYSTEM PROMPT (Task 1)                                      │
│    - Clear security rules that resist injection                         │
│    - Explicit forbidden operations                                      │
│    - Guidance for handling sensitive requests                          │
│    Blocks: ~20-30% of attacks                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. INPUT VALIDATION (Task 2)                                            │
│    - Analyzes user requests for malicious patterns                      │
│    - Detects override attempts, authority spoofing, etc.               │
│    - Blocks requests before they reach the LLM                         │
│    Blocks: ~60-80% of remaining attacks                                │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ 3. MAIN LLM PROCESSING                                                   │
│    - Uses hardened system prompt                                        │
│    - Trained to resist injections                                       │
│    - Processes legitimate requests                                      │
│    Risk: LLM might still leak PII due to training data                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ 4. OUTPUT VALIDATION (Task 3A & 3B)                                     │
│    - Detects PII in responses using Presidio                            │
│    - Redacts or blocks sensitive information                            │
│    - Streaming version for real-time filtering                         │
│    Blocks: 100% of PII leaks (but may have false positives)            │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
                            SAFE USER RESPONSE


KEY LEARNINGS:

✓ DEFENSE IN DEPTH: Multiple layers are more secure than one strong layer
✓ SEPARATION OF CONCERNS: Each layer has a specific responsibility
✓ NO SILVER BULLET: Each technique has limitations
✓ CONTEXT MATTERS: What's a false positive depends on your application
✓ TESTING IS CRITICAL: Always test with real attack examples


WHEN TO USE EACH:

Task 1 - Always: Use hardened system prompts in all applications
Task 2 - Critical apps: Add input validation for security-sensitive systems
Task 3A - Financial/Health: Add output validation for sensitive data handling
Task 3B - Streaming UIs: Use for real-time filtering in web applications


NEXT STEPS:

1. Experiment with different attack examples from PROMPT_INJECTIONS_TO_TEST.md
2. Adjust safety thresholds and test trade-offs
3. Try different combinations of hardness vs permissiveness
4. Integrate into your application architecture
5. Monitor and log blocked requests for security insights


PRODUCTION CONSIDERATIONS:

⚠️  These are educational implementations!
    - Presidio is good but not perfect for all PII types
    - LLM-based validation has latency and cost implications
    - Test thoroughly with your specific threat model
    - Consider using guardrails-ai framework for production

📊 Monitoring:
    - Track false positive rates
    - Log blocked requests
    - Monitor LLM behavior over time
    - Set up alerts for suspicious patterns

🔒 Additional Layers to Consider:
    - User authentication and rate limiting
    - API key management and rotation
    - Network-level security
    - Data encryption in transit and at rest
    - Regular security audits and penetration testing


RESOURCES & LINKS:

- Presidio: https://github.com/microsoft/presidio
- OWASP Prompt Injection: https://owasp.org/www-community/attacks/Prompt_Injection
- LangChain: https://python.langchain.com/
- Guardrails AI: https://www.guardrails.ai/


THANK YOU FOR COMPLETING THIS LEARNING JOURNEY! 🎓
"""
    print(summary)


def main() -> None:
    """Main entry point - run all tasks in sequence."""
    
    print("\n")
    print("╔════════════════════════════════════════════════════════════════════════════╗")
    print("║             AI GUARDRAILS - COMPREHENSIVE SECURITY TASKS                   ║")
    print("║                                                                            ║")
    print("║  Learn to protect AI applications from prompt injection and PII leaks      ║")
    print("╚════════════════════════════════════════════════════════════════════════════╝")
    
    while True:
        print("\nWhich task would you like to run?")
        print("\n1. Task 1: Prompt Injection Defense - System Prompt Hardening")
        print("2. Task 2: Input Validation - Detect Malicious Requests")
        print("3. Task 3A: Output Validation - Prevent PII Leaks")
        print("4. Task 3B: Streaming - Real-time PII Filtering")
        print("5. Run All Tasks in Sequence")
        print("6. View Final Summary")
        print("0. Exit")
        
        choice = input("\nEnter your choice (0-6): ").strip()
        
        try:
            if choice == "1":
                run_task_1()
            elif choice == "2":
                run_task_2()
            elif choice == "3":
                run_task_3a()
            elif choice == "4":
                run_task_3b()
            elif choice == "5":
                run_task_1()
                input("\nPress Enter to continue to Task 2...")
                run_task_2()
                input("\nPress Enter to continue to Task 3A...")
                run_task_3a()
                input("\nPress Enter to continue to Task 3B...")
                run_task_3b()
                input("\nPress Enter to see Final Summary...")
                print_final_summary()
            elif choice == "6":
                print_final_summary()
            elif choice == "0":
                print("\nThank you for learning about AI guardrails! Goodbye!")
                break
            else:
                print("\nInvalid choice. Please enter 0-6.")
        
        except KeyboardInterrupt:
            print("\n\nInterrupted by user. Goodbye!")
            break
        except Exception as e:
            print(f"\nError running task: {e}")
            print("Note: Make sure your DIAL_API_KEY environment variable is set correctly.")


if __name__ == "__main__":
    main()
