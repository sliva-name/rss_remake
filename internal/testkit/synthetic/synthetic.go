// Package synthetic generates fake personal data for tests. Values are
// format-valid and pass checksums but use reserved ranges or markers, so they
// identify nobody. The canary marker lets leak tests search for them later.
package synthetic

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

// CanaryMarker appears in generated text values; finding it outside the source
// database proves a leak.
const CanaryMarker = "dgcanary"

// Generator is deterministic so a failing test can be reproduced from its seed.
type Generator struct {
	random *rand.Rand
}

func New(seed uint64) *Generator {
	//nolint:gosec // Tests need reproducible values, not unpredictable ones.
	return &Generator{random: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

// Email uses the reserved .invalid top-level domain.
func (g *Generator) Email() string {
	return fmt.Sprintf("%s.%06d@example.invalid", CanaryMarker, g.random.IntN(1_000_000))
}

// PhoneRU uses the Russian country code with a random subscriber number.
func (g *Generator) PhoneRU() string {
	return fmt.Sprintf("+79%09d", g.random.IntN(1_000_000_000))
}

func (g *Generator) digits(count int) []int {
	digits := make([]int, count)
	for i := range digits {
		digits[i] = g.random.IntN(10)
	}
	return digits
}

func weightedRemainder(digits, weights []int) int {
	sum := 0
	for i, weight := range weights {
		sum += digits[i] * weight
	}
	return sum % 11 % 10
}

func join(digits []int) string {
	var builder strings.Builder
	for _, digit := range digits {
		builder.WriteString(strconv.Itoa(digit))
	}
	return builder.String()
}

// INN12 returns a 12-digit individual tax number with valid check digits.
func (g *Generator) INN12() string {
	digits := g.digits(10)
	digits = append(digits, weightedRemainder(digits, []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}))
	digits = append(digits, weightedRemainder(digits, []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}))
	return join(digits)
}

// INN10 returns a 10-digit organization tax number with a valid check digit.
func (g *Generator) INN10() string {
	digits := g.digits(9)
	digits = append(digits, weightedRemainder(digits, []int{2, 4, 10, 3, 5, 9, 4, 6, 8}))
	return join(digits)
}

// SNILS returns an insurance number with a valid control pair.
func (g *Generator) SNILS() string {
	digits := g.digits(9)
	sum := 0
	for i, digit := range digits {
		sum += digit * (9 - i)
	}
	control := sum % 101
	if control == 100 {
		control = 0
	}
	body := join(digits)
	return fmt.Sprintf("%s-%s-%s %02d", body[:3], body[3:6], body[6:9], control)
}

// PaymentCard returns a Luhn-valid number in the 4000 00 test-card range.
func (g *Generator) PaymentCard() string {
	digits := append([]int{4, 0, 0, 0, 0, 0}, g.digits(9)...)
	sum := 0
	for i, digit := range digits {
		if i%2 == 0 {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return join(append(digits, (10-sum%10)%10))
}

// PassportRU returns a series and number with the conventional space.
func (g *Generator) PassportRU() string {
	return fmt.Sprintf("%04d %06d", g.random.IntN(10_000), g.random.IntN(1_000_000))
}

// RandomDigits returns digits with no checksum: the negative case for detectors.
func (g *Generator) RandomDigits(count int) string {
	return join(g.digits(count))
}
