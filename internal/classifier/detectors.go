package classifier

import (
	"bytes"
	"regexp"
	"slices"
)

const (
	minCardDigits    = 13
	maxCardDigits    = 19
	innOrgDigits     = 10
	innPersonDigits  = 12
	snilsDigits      = 11
	snilsBodyDigits  = 9
	snilsMaxPlain    = 100
	snilsModulus     = 101
	passportDigits   = 10
	phoneRUDigits    = 11
	minE164Digits    = 10
	maxE164Digits    = 15
	maxPhoneLength   = 24
	maxEmailLength   = 254
	maxFormattedText = 32
	modulus11        = 11
	decimal          = 10
	luhnDoubleLimit  = 9
)

var (
	emailShape = regexp.MustCompile(`^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$`)
	// Separators make a number look like a phone, which bare digits do not.
	phoneShape    = regexp.MustCompile(`^\+?[0-9][0-9 ()\-]{8,}[0-9]$`)
	snilsShape    = regexp.MustCompile(`^[0-9]{3}-[0-9]{3}-[0-9]{3}[ -][0-9]{2}$`)
	passportShape = regexp.MustCompile(`^[0-9]{2} ?[0-9]{2} ?[0-9]{6}$`)
)

func builtinDetectors() []Detector {
	return []Detector{
		email{}, phone{}, taxID{}, snils{}, paymentCard{}, passport{},
	}
}

func builtinMetadataRules() []MetadataRule {
	return []MetadataRule{
		{CategoryPersonName, regexp.MustCompile(`(^|_)(first|last|middle|full|given|sur)_?name($|_)|(^|_)(fio|patronymic|surname|imya|familiya|otchestvo)($|_)|фио|фамилия`)},
		{CategoryBirthDate, regexp.MustCompile(`(^|_)(date_of_birth|birth_?date|birthday|dob)($|_)|дата рождения`)},
		{CategoryAddress, regexp.MustCompile(`(^|_)(address|street|postal_?code|zip_?code)($|_)|адрес`)},
		{CategoryBankAccount, regexp.MustCompile(`(^|_)(iban|bic|bank_?account|account_?number|swift)($|_)|расч[её]тный сч[её]т`)},
		{CategoryPassword, regexp.MustCompile(`(^|_)(pass|passwd|password|pwd)(_?hash)?($|_)|пароль`)},
		{CategorySecret, regexp.MustCompile(`(^|_)(secret|api_?key|access_?token|refresh_?token|private_?key)($|_)`)},
		{CategoryMedical, regexp.MustCompile(`(^|_)(diagnosis|medical_?record|icd_?code)($|_)|диагноз`)},
	}
}

type email struct{}

var (
	emailName = regexp.MustCompile(`(^|_)e?_?mail(_|$)|почта`)
)

func (email) Category() string               { return CategoryEmail }
func (email) NamePattern() *regexp.Regexp    { return emailName }
func (email) ContextPattern() *regexp.Regexp { return nil }
func (email) HasChecksum() bool              { return false }
func (email) RequiresContext() bool          { return false }
func (email) Inspect(value []byte, _ bool) Verdict {
	return Verdict{Format: len(value) <= maxEmailLength && emailShape.Match(bytes.TrimSpace(value))}
}

type phone struct{}

var phoneName = regexp.MustCompile(`(^|_)(phone|mobile|msisdn|tel|telephone)(_|$)|телефон`)

func (phone) Category() string               { return CategoryPhone }
func (phone) NamePattern() *regexp.Regexp    { return phoneName }
func (phone) ContextPattern() *regexp.Regexp { return nil }
func (phone) HasChecksum() bool              { return false }
func (phone) RequiresContext() bool          { return false }

// Inspect accepts bare digits only when the name agrees: eleven digits alone
// are as likely an order number as a phone.
func (phone) Inspect(value []byte, hasContext bool) Verdict {
	text := bytes.TrimSpace(value)
	if len(text) > maxPhoneLength || !phoneShape.Match(text) {
		return Verdict{}
	}
	digits := countDigits(text)
	switch {
	case text[0] == '+':
		return Verdict{Format: digits >= minE164Digits && digits <= maxE164Digits}
	case digits == phoneRUDigits && (text[0] == '7' || text[0] == '8'):
		return Verdict{Format: hasContext || digits != len(text)}
	default:
		return Verdict{}
	}
}

type taxID struct{}

var taxIDName = regexp.MustCompile(`(^|_)(inn|tax_?id|taxpayer_?id|vat_?id)(_|$)|инн`)

func (taxID) Category() string               { return CategoryTaxID }
func (taxID) NamePattern() *regexp.Regexp    { return taxIDName }
func (taxID) ContextPattern() *regexp.Regexp { return nil }
func (taxID) HasChecksum() bool              { return true }
func (taxID) RequiresContext() bool          { return false }

func (taxID) Inspect(value []byte, _ bool) Verdict {
	digits, ok := plainDigits(value)
	if !ok || (len(digits) != innOrgDigits && len(digits) != innPersonDigits) {
		return Verdict{}
	}
	return Verdict{Format: true, Checksum: validINN(digits)}
}

var (
	inn10Weights  = []int{2, 4, 10, 3, 5, 9, 4, 6, 8}
	inn12Weights1 = []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	inn12Weights2 = []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
)

func validINN(digits []int) bool {
	if len(digits) == innOrgDigits {
		return weightedCheck(digits, inn10Weights) == digits[innOrgDigits-1]
	}
	return weightedCheck(digits, inn12Weights1) == digits[innPersonDigits-2] &&
		weightedCheck(digits, inn12Weights2) == digits[innPersonDigits-1]
}

func weightedCheck(digits, weights []int) int {
	sum := 0
	for i, weight := range weights {
		sum += digits[i] * weight
	}
	return sum % modulus11 % decimal
}

type snils struct{}

var snilsName = regexp.MustCompile(`(^|_)snils(_|$)|снилс`)

func (snils) Category() string               { return CategorySNILS }
func (snils) NamePattern() *regexp.Regexp    { return snilsName }
func (snils) ContextPattern() *regexp.Regexp { return nil }
func (snils) HasChecksum() bool              { return true }
func (snils) RequiresContext() bool          { return false }

func (snils) Inspect(value []byte, _ bool) Verdict {
	text := bytes.TrimSpace(value)
	if len(text) > maxFormattedText {
		return Verdict{}
	}
	digits := extractDigits(text)
	formatted := snilsShape.Match(text)
	if len(digits) != snilsDigits || (!formatted && len(text) != snilsDigits) {
		return Verdict{}
	}
	return Verdict{Format: true, Checksum: validSNILS(digits)}
}

func validSNILS(digits []int) bool {
	sum := 0
	for i := range snilsBodyDigits {
		sum += digits[i] * (snilsBodyDigits - i)
	}
	control := sum % snilsModulus
	if control == snilsMaxPlain {
		control = 0
	}
	return control == digits[snilsBodyDigits]*decimal+digits[snilsBodyDigits+1]
}

type paymentCard struct{}

var cardName = regexp.MustCompile(`(^|_)(card|pan|cc)(_?(number|no|num))?(_|$)|номер карты`)

func (paymentCard) Category() string               { return CategoryPaymentCard }
func (paymentCard) NamePattern() *regexp.Regexp    { return cardName }
func (paymentCard) ContextPattern() *regexp.Regexp { return nil }
func (paymentCard) HasChecksum() bool              { return true }
func (paymentCard) RequiresContext() bool          { return false }

func (paymentCard) Inspect(value []byte, _ bool) Verdict {
	text := bytes.TrimSpace(value)
	if len(text) > maxFormattedText {
		return Verdict{}
	}
	digits := extractDigits(bytes.Map(dropCardSeparator, text))
	if len(digits) != countAll(text) || len(digits) < minCardDigits || len(digits) > maxCardDigits {
		return Verdict{}
	}
	return Verdict{Format: true, Checksum: validLuhn(digits)}
}

func dropCardSeparator(r rune) rune {
	if r == ' ' || r == '-' {
		return -1
	}
	return r
}

func countAll(text []byte) int {
	return len(bytes.Map(dropCardSeparator, text))
}

func validLuhn(digits []int) bool {
	sum := 0
	double := false
	for _, digit := range slices.Backward(digits) {
		if double {
			digit *= 2
			if digit > luhnDoubleLimit {
				digit -= luhnDoubleLimit
			}
		}
		sum += digit
		double = !double
	}
	return sum%decimal == 0
}

type passport struct{}

var (
	passportName    = regexp.MustCompile(`(^|_)passport(_|$)|паспорт`)
	passportContext = regexp.MustCompile(`passport|паспорт|identity_document`)
)

func (passport) Category() string               { return CategoryPassport }
func (passport) NamePattern() *regexp.Regexp    { return passportName }
func (passport) ContextPattern() *regexp.Regexp { return passportContext }
func (passport) HasChecksum() bool              { return false }
func (passport) RequiresContext() bool          { return true }

func (passport) Inspect(value []byte, _ bool) Verdict {
	text := bytes.TrimSpace(value)
	return Verdict{Format: passportShape.Match(text) && countDigits(text) == passportDigits}
}

func plainDigits(value []byte) ([]int, bool) {
	text := bytes.TrimSpace(value)
	if len(text) == 0 || len(text) > maxFormattedText {
		return nil, false
	}
	digits := extractDigits(text)
	return digits, len(digits) == len(text)
}

func extractDigits(text []byte) []int {
	digits := make([]int, 0, len(text))
	for _, char := range text {
		if char >= '0' && char <= '9' {
			digits = append(digits, int(char-'0'))
		}
	}
	return digits
}

func countDigits(text []byte) int {
	count := 0
	for _, char := range text {
		if char >= '0' && char <= '9' {
			count++
		}
	}
	return count
}
