"""
Password Strength Checker
A beginner-friendly tool to evaluate password strength based on common security criteria.

Learning concepts:
- String manipulation
- Regular expressions
- Security best practices
"""

import re
import sys


def check_password_strength(password: str) -> dict:
    """
    Evaluate password strength and return detailed feedback.
    
    Args:
        password: The password to evaluate
        
    Returns:
        dict: Contains 'strength' (weak/medium/strong/very_strong) and 'feedback'
    """
    feedback = []
    score = 0
    max_score = 6
    
    # Check length
    if len(password) >= 8:
        score += 1
        if len(password) >= 12:
            score += 1
    else:
        feedback.append("❌ Password should be at least 8 characters long")
    
    # Check for uppercase letters
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("❌ Add uppercase letters (A-Z)")
    
    # Check for lowercase letters
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("❌ Add lowercase letters (a-z)")
    
    # Check for digits
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("❌ Add numbers (0-9)")
    
    # Check for special characters
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        score += 1
    else:
        feedback.append("❌ Add special characters (!@#$%^&*)")
    
    # Determine strength level
    if score >= 5:
        strength = "very_strong"
        feedback.insert(0, "✅ Very Strong Password!")
    elif score >= 4:
        strength = "strong"
        feedback.insert(0, "✅ Strong Password")
    elif score >= 2:
        strength = "medium"
        feedback.insert(0, "⚠️  Medium Password - Could be better")
    else:
        strength = "weak"
        feedback.insert(0, "❌ Weak Password - Needs improvement")
    
    return {
        'strength': strength,
        'score': f"{score}/{max_score}",
        'feedback': feedback
    }


def main():
    """Main function to run the password checker."""
    print("=" * 50)
    print("🔐 PASSWORD STRENGTH CHECKER")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        password = sys.argv[1]
    else:
        password = input("\nEnter a password to check: ")
    
    result = check_password_strength(password)
    
    print(f"\nPassword Length: {len(password)} characters")
    print(f"Strength Level: {result['strength'].upper()}")
    print(f"Score: {result['score']}")
    print("\nFeedback:")
    for item in result['feedback']:
        print(f"  {item}")
    
    print("\n" + "=" * 50)


if __name__ == "__main__":
    main()
