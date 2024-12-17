package tokenmanager

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

// JWTManager manages JWT tokens
type JWTManager struct {
	secretKey     string
	tokenDuration time.Duration
}

type UserClaims struct {
	jwt.StandardClaims
	UserId     uint64 `json:"userId"`
	EndDate    string `json:"endDate,omitempty"`
	ScopesMask int    `json:"scopes"`
}

// Constants of bit masks for scopes
const (
	ScopeFree    = 0x001
	ScopePremium = 0x002
)

// NewJWTManager creates a new instance of JWTManager
func NewJWTManager(secretKey string, tokenDuration time.Duration) *JWTManager {
	return &JWTManager{secretKey, tokenDuration}
}

// GenerateWithScopes generates JWT token with scopes
func (manager *JWTManager) GenerateWithScopes(userId uint64, endDate string, scopesMask int) (string, error) {
	claims := UserClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(manager.tokenDuration).Unix(),
		},
		UserId:     userId,
		EndDate:    endDate,
		ScopesMask: scopesMask,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(manager.secretKey))
}

// VerifyWithScopes verifies JWT and returns user ID and scopes
func (manager *JWTManager) VerifyWithScopes(accessToken string, language string) (*uint64, *string, []string, error) {
	token, err := jwt.ParseWithClaims(
		accessToken,
		&UserClaims{},
		func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("unexpected token signing method")
			}
			return []byte(manager.secretKey), nil
		},
	)

	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || claims.EndDate == "" {
		return nil, nil, nil, fmt.Errorf("invalid token claims or missing subscription data")
	}

	// decode scopes
	scopes := DecodeScopes(claims.ScopesMask, language)

	return &claims.UserId, &claims.EndDate, scopes, nil
}

// DecodeScopes decode a bitmask of scopes in a list of permissions
func DecodeScopes(scopesMask int, language string) []string {
	languageDictionary := map[string]map[string]string{
		"free":    {"ru": "Общий", "en": "Free"},
		"premium": {"ru": "Премиум", "en": "Premium"},
	}

	var scopes []string

	if scopesMask&ScopeFree == ScopeFree {
		scopes = append(scopes, languageDictionary["free"][language])
	}
	if scopesMask&ScopePremium == ScopePremium {
		scopes = append(scopes, languageDictionary["premium"][language])
	}

	return scopes
}

func EncodeScopes(scopes []string) int {
	scopeMap := map[string]int{
		"free":    ScopeFree,
		"premium": ScopePremium,
	}

	mask := 0
	for _, scope := range scopes {
		if val, exists := scopeMap[scope]; exists {
			mask |= val
		}
	}

	return mask
}
