/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package credentials

import (
	"regexp"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceCreditCard = "CreditCard"

var (
	// Credit card pattern - matches common formats
	// Supports: 1234567890123456, 1234-5678-9012-3456, 1234 5678 9012 3456
	reCreditCard = regexp.MustCompile(`\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b`)

	// Additional patterns for specific card types
	// Visa: starts with 4, 13-16 digits
	reVisa = regexp.MustCompile(`\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b`)

	// MasterCard: starts with 51-55 or 2221-2720, 16 digits
	reMasterCard = regexp.MustCompile(`\b(?:5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[0-1]\d|2720)[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b`)

	// American Express: starts with 34 or 37, 15 digits
	reAmex = regexp.MustCompile(`\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b`)

	// Discover: starts with 6011, 622126-622925, 644-649, or 65, 16 digits
	reDiscover = regexp.MustCompile(`\b(?:6011|622[1-9]|64[4-9]\d|65\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b`)
)

// creditCardHarvester detects credit card numbers in network traffic
// NOTE: This can produce false positives and should be used with caution
// It uses the Luhn algorithm to validate potential card numbers
// This harvester is OPTIONAL and should be enabled via configuration
func creditCardHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	// Convert to string for regex matching
	dataStr := string(data)

	// Find all potential credit card numbers
	matches := reCreditCard.FindAllString(dataStr, -1)

	for _, match := range matches {
		// Remove spaces and dashes
		cardNum := strings.ReplaceAll(match, " ", "")
		cardNum = strings.ReplaceAll(cardNum, "-", "")

		// Validate with Luhn algorithm
		if !luhnCheck(cardNum) {
			continue
		}

		// Determine card type
		cardType := identifyCreditCardType(cardNum)

		// Extract surrounding context for notes
		matchIdx := strings.Index(dataStr, match)
		contextStart := matchIdx - 50
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := matchIdx + len(match) + 50
		if contextEnd > len(dataStr) {
			contextEnd = len(dataStr)
		}
		context := dataStr[contextStart:contextEnd]

		// Sanitize context (remove control characters)
		context = strings.Map(func(r rune) rune {
			if r < 32 || r > 126 {
				return ' '
			}
			return r
		}, context)

		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceCreditCard,
			Flow:      ident,
			User:      cardType,
			Password:  maskCreditCard(cardNum), // Store masked version for privacy
			Notes:     "Luhn check passed. Context: " + strings.TrimSpace(context),
		}
	}

	return nil
}

// luhnCheck validates a credit card number using the Luhn algorithm
// Also known as the "modulus 10" or "mod 10" algorithm
func luhnCheck(cardNum string) bool {
	// Remove any non-digit characters
	digits := ""
	for _, ch := range cardNum {
		if ch >= '0' && ch <= '9' {
			digits += string(ch)
		}
	}

	// Card number should be 13-19 digits
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alternate := false

	// Process digits from right to left
	for i := len(digits) - 1; i >= 0; i-- {
		digit := int(digits[i] - '0')

		if alternate {
			digit *= 2
			if digit > 9 {
				digit = (digit % 10) + 1
			}
		}

		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}

// identifyCreditCardType identifies the card type based on the number
func identifyCreditCardType(cardNum string) string {
	if len(cardNum) < 2 {
		return "Unknown"
	}

	// Check specific patterns
	if reVisa.MatchString(cardNum) {
		return "Visa"
	}
	if reMasterCard.MatchString(cardNum) {
		return "MasterCard"
	}
	if reAmex.MatchString(cardNum) {
		return "American Express"
	}
	if reDiscover.MatchString(cardNum) {
		return "Discover"
	}

	// Check by starting digits
	prefix2 := cardNum[:2]
	prefix4 := ""
	if len(cardNum) >= 4 {
		prefix4 = cardNum[:4]
	}

	switch {
	case cardNum[0] == '4':
		return "Visa"
	case prefix2 >= "51" && prefix2 <= "55":
		return "MasterCard"
	case prefix2 == "34" || prefix2 == "37":
		return "American Express"
	case prefix4 == "6011":
		return "Discover"
	case prefix2 == "35":
		return "JCB"
	case prefix2 == "36" || prefix2 == "38":
		return "Diners Club"
	default:
		return "Unknown"
	}
}

// maskCreditCard masks a credit card number for safe storage
// Shows only first 6 and last 4 digits
func maskCreditCard(cardNum string) string {
	if len(cardNum) <= 10 {
		return "****" + cardNum[len(cardNum)-4:]
	}

	return cardNum[:6] + strings.Repeat("*", len(cardNum)-10) + cardNum[len(cardNum)-4:]
}

// validateCreditCardContext checks if the surrounding context looks legitimate
// This helps reduce false positives by checking for transaction-related keywords
func validateCreditCardContext(context string) bool {
	// Look for transaction-related keywords
	keywords := []string{
		"card", "credit", "payment", "transaction", "cvv", "expir",
		"billing", "purchase", "amount", "total", "charge",
	}

	lowerContext := strings.ToLower(context)
	for _, keyword := range keywords {
		if strings.Contains(lowerContext, keyword) {
			return true
		}
	}

	return false
}







